// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "injector.h"

#include "dict.h"
#include "query.h"
#include "address.h"
#include "message.h"
#include "ustring.h"
#include "bodypart.h"
#include "mailbox.h"
#include "mimefields.h"
#include "fieldcache.h"
#include "addresscache.h"
#include "transaction.h"
#include "allocator.h"
#include "occlient.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "scope.h"

#include <time.h>


class IdHelper;

static PreparedStatement *lockUidnext;
static PreparedStatement *incrUidnext;
static PreparedStatement *idBodypart;
static PreparedStatement *fixBodypart;
static PreparedStatement *intoBodyparts;
static PreparedStatement *intoMessages;
static PreparedStatement *intoRecent;
static PreparedStatement *intoPartnumbers;
static PreparedStatement *intoHeaderfields;
static PreparedStatement *intoAddressfields;


// These structs represent one part of each entry in the header_fields
// and address_fields tables. (The other part being mailbox and UID.)

struct FieldLink {
    HeaderField *hf;
    String part;
};

struct AddressLink {
    Address * address;
    HeaderField::Type type;
};


class InjectorData {
public:
    InjectorData()
        : step( 0 ), failed( false ), idate( time( 0 ) ),
          owner( 0 ), message( 0 ), mailboxes( 0 ), transaction( 0 ),
          totalUids( 0 ), uids( 0 ), totalBodyparts( 0 ), bodypartIds( 0 ),
          bodyparts( 0 ), addressLinks( 0 ), fieldLinks( 0 ), otherFields( 0 ),
          fieldLookup( 0 ), addressLookup( 0 ), bidHelper( 0 )
    {}

    int step;
    bool failed;

    int idate;
    EventHandler * owner;
    const Message * message;
    SortedList< Mailbox > * mailboxes;

    Transaction * transaction;

    uint totalUids;
    List< uint > * uids;
    uint totalBodyparts;
    List< uint > * bodypartIds;
    List< Bodypart > * bodyparts;
    List< AddressLink > * addressLinks;
    List< FieldLink > * fieldLinks;
    List< String > * otherFields;

    CacheLookup * fieldLookup;
    CacheLookup * addressLookup;
    IdHelper * bidHelper;
};


class IdHelper : public EventHandler {
private:
    List< uint > * list;
    List< Query > * queries;
    EventHandler * owner;

public:
    bool failed;

    IdHelper( List< uint > *l, List< Query > *q, EventHandler *ev )
        : list( l ), queries( q ), owner( ev ), failed( false )
    {}

    virtual void processResults( Query *q ) {
        list->append( new uint( q->nextRow()->getInt( 0 ) ) );
    }

    void execute() {
        Query *q = queries->first();
        if ( !q || !q->done() )
            return;

        if ( q->hasResults() )
            processResults( q );
        else
            failed = true;

        queries->take( queries->first() );
        if ( queries->isEmpty() )
            owner->execute();
    }
};


/*! \class Injector injector.h
    This class delivers a Message to a List of Mailboxes.

    The Injector takes a Message object, and performs all the database
    operations necessary to inject it into each of a List of Mailboxes.
    The message is assumed to be valid. The list of mailboxes must be
    sorted.
*/

/*! This setup function expects to be called by ::main() to perform what
    little initialisation is required by the Injector.
*/

void Injector::setup()
{
    lockUidnext =
        new PreparedStatement(
            "select uidnext from mailboxes where id=$1 for update"
        );
    Allocator::addEternal( lockUidnext, "lockUidnext" );

    incrUidnext =
        new PreparedStatement(
            "update mailboxes set uidnext=uidnext+1 where id=$1"
        );
    Allocator::addEternal( incrUidnext, "incrUidnext" );

    idBodypart =
        new PreparedStatement(
            "select id from bodyparts where hash=$1"
        );
    Allocator::addEternal( idBodypart, "idBodypart" );

    fixBodypart =
        new PreparedStatement(
            "update bodyparts set lines=$2 where hash=$1"
        );
    Allocator::addEternal( fixBodypart, "fixBodypart" );

    intoBodyparts =
        new PreparedStatement(
            "insert into bodyparts (hash,bytes,lines,text,data) "
            "values ($1,$2,42,$3,$4)"
        );
    Allocator::addEternal( intoBodyparts, "intoBodyparts" );

    intoMessages =
        new PreparedStatement(
            "insert into messages (mailbox,uid,idate,rfc822size) "
            "values ($1,$2,$3,$4)"
        );
    Allocator::addEternal( intoMessages, "intoMessages" );

    intoRecent =
        new PreparedStatement(
            "insert into recent_messages (mailbox,uid) values ($1,$2)"
        );
    Allocator::addEternal( intoRecent, "intoRecent" );

    intoPartnumbers =
        new PreparedStatement(
            "insert into part_numbers (mailbox,uid,part,bodypart) "
            "values ($1,$2,$3,$4)"
        );
    Allocator::addEternal( intoPartnumbers, "intoPartnumbers" );

    intoHeaderfields =
        new PreparedStatement(
            "insert into header_fields "
            "(mailbox,uid,part,field,value) values "
            "($1,$2,$3,$4,$5)"
        );
    Allocator::addEternal( intoHeaderfields, "intoHeaderfields" );

    intoAddressfields =
        new PreparedStatement(
            "insert into address_fields "
            "(mailbox,uid,field,address) values "
            "($1,$2,$3,$4)"
        );
    Allocator::addEternal( intoAddressfields, "intoAddressfields" );
}


/*! Creates a new Injector object to deliver the \a message into each of
    the \a mailboxes on behalf of the \a owner, which is notified when
    the delivery attempt is completed. Message delivery commences when
    the execute() function is called.

    The caller must not change \a mailboxes after this call.
*/

Injector::Injector( const Message * message,
                    SortedList< Mailbox > * mailboxes,
                    EventHandler * owner )
    : d( new InjectorData )
{
    if ( !lockUidnext )
        setup();
    d->owner = owner;
    d->message = message;
    d->mailboxes = mailboxes;
}


/*! Cleans up after injection. (We're already pretty clean.) */

Injector::~Injector()
{
}


/*! Returns true if this injector has finished its work, and false if it
    hasn't started or is currently working.
*/

bool Injector::done() const
{
    return ( d->step >= 5 || d->failed );
}


/*! Returns true if this injection failed, and false if it has succeeded
    or is in progress.
*/

bool Injector::failed() const
{
    return d->failed;
}


/*! This function creates and executes the series of database queries
    needed to perform message delivery.
*/

void Injector::execute()
{
    Scope x( log() );

    // Conceptually, the Injector does its work in a single transaction.
    // In practice, however, the need to maintain unique entries in the
    // bodyparts table demands either an exclusive lock (which we would
    // rather avoid), the use of savepoints (only in PG8), or INSERTing
    // bodyparts entries outside the transaction to tolerate failure.
    //
    // -- AMS 20050412

    if ( d->step == 0 ) {
        // We begin by obtaining a UID for each mailbox we are injecting
        // a message into, and simultaneously inserting entries into the
        // bodyparts table. At the same time, we can begin to lookup and
        // insert the addresses and field names used in the message.

        logMessageDetails();

        d->transaction = new Transaction( this );
        d->bodyparts = d->message->allBodyparts();

        // The bodyparts inserts happen outside d->transaction.
        insertBodyparts();
        selectUids();
        buildAddressLinks();
        buildFieldLinks();

        d->transaction->execute();
        d->step = 1;
    }

    if ( d->step == 1 && !d->transaction->failed() ) {
        // Once we have UIDs for each Mailbox, we can insert rows into
        // messages and recent_messages.

        if ( d->uids->count() != d->totalUids )
            return;

        insertMessages();

        d->transaction->execute();
        d->step = 2;
    }

    if ( d->step == 2 && !d->transaction->failed() ) {
        // We expect buildFieldLinks() to have completed immediately.
        // Once insertBodyparts() is completed, we can start adding to
        // the part_numbers and header_fields tables.

        // Since the bodyparts inserts are outside the transaction, we
        // have to take particular care about handling errors there.
        if ( d->bidHelper->failed ) {
            d->transaction->rollback();
            d->failed = true;
            d->step = 5;
        }

        if ( !d->fieldLookup->done() ||
             d->bodypartIds->count() != d->totalBodyparts )
            return;

        linkBodyparts();
        linkHeaderFields();

        d->transaction->execute();
        d->step = 3;
    }

    if ( d->step == 3 && !d->transaction->failed() ) {
        // Fill in address_fields once the address lookup is complete.
        // (We could have done this without waiting for the bodyparts
        // to be inserted, but it didn't seem worthwhile.)

        if ( !d->addressLookup->done() )
            return;

        linkAddresses();
        d->step = 4;
    }

    if ( d->step == 4 || d->transaction->failed() ) {
        // Now we just wait for everything to finish.
        if ( d->step < 5 )
            d->transaction->commit();
        d->step = 5;
    }

    if ( d->step == 5 ) {
        if ( !d->transaction->done() )
            return;
        if ( !d->failed )
            d->failed = d->transaction->failed();

        // XXX: If we fail early in the transaction, we'll continue to
        // be notified of individual query failures. We don't want to
        // pass them on, because d->owner would have killed itself.
        if ( d->owner ) {
            if ( d->failed )
                log( "Injection failed: " + d->transaction->error() );
            else
                log( "Injection succeeded" );
            d->owner->execute();
            d->owner = 0;
        }
    }
}


/*! This private function issues queries to retrieve a UID for each of
    the Mailboxes we are delivering the message into, adds each UID to
    d->uids, and informs execute() when it's done.
*/

void Injector::selectUids()
{
    Query *q;
    d->uids = new List< uint >;
    List< Query > * queries = new List< Query >;
    IdHelper * helper = new IdHelper( d->uids, queries, this );

    List< Mailbox >::Iterator it( d->mailboxes->first() );
    while ( it ) {
        d->totalUids++;

        // We acquire a write lock on our mailbox, and hold it until the
        // entire transaction has committed successfully. We use uidnext
        // in lieu of a UID sequence to serialise Injectors, so that UID
        // announcements are correctly ordered.
        //
        // The mailbox list must be sorted, so that Injectors always try
        // to acquire locks in the same order, thus avoiding deadlocks.

        q = new Query( *lockUidnext, helper );
        q->bind( 1, it->id() );
        d->transaction->enqueue( q );
        queries->append( q );

        q = new Query( *incrUidnext, helper );
        q->bind( 1, it->id() );
        d->transaction->enqueue( q );

        ++it;
    }
}


/*! This private function builds a list of AddressLinks containing every
    address used in the message, and initiates an AddressCache::lookup()
    after excluding any duplicate addresses. It causes execute() to be
    called when every address in d->addressLinks has been resolved.
*/

void Injector::buildAddressLinks()
{
    d->addressLinks = new List< AddressLink >;
    List< Address > * addresses = new List< Address >;
    Dict< Address > unique;

    int i = 0;
    while ( i <= HeaderField::LastAddressField ) {
        HeaderField::Type t = (HeaderField::Type)i++;
        List< Address > * a = d->message->header()->addresses( t );
        if ( a && !a->isEmpty() ) {
            List< Address >::Iterator it( a->first() );
            while ( it ) {
                Address *a = it;
                String k = a->toString();

                if ( unique.contains( k ) ) {
                    a = unique.find( k );
                }
                else {
                    unique.insert( k, a );
                    addresses->append( a );
                }

                AddressLink *link = new AddressLink;
                d->addressLinks->append( link );
                link->address = a;
                link->type = t;

                ++it;
            }
        }
    }

    d->addressLookup =
        AddressCache::lookup( d->transaction, addresses, this );
}


/*! This private function builds a list of FieldLinks containing every
    header field used in the message, and uses
    FieldNameCache::lookup() to associate each unknown HeaderField
    with an ID. It causes execute() to be called when every field name
    in d->fieldLinks has been resolved.
*/

void Injector::buildFieldLinks()
{
    d->fieldLinks = new List< FieldLink >;
    d->otherFields = new List< String >;

    buildLinksForHeader( d->message->header(), "" );

    // Since the MIME header fields belonging to the first-child of a
    // single-part Message are physically collocated with the RFC 822
    // header, we don't need to inject them into the database again.
    bool skip = false;
    ContentType *ct = d->message->header()->contentType();
    if ( !ct || ct->type() != "multipart" )
        skip = true;

    List< Bodypart >::Iterator it( d->bodyparts->first() );
    while ( it ) {
        String pn = d->message->partNumber( it );

        if ( !skip )
            buildLinksForHeader( it->header(), pn );
        else
            skip = false;

        if ( it->rfc822() )
            buildLinksForHeader( it->rfc822()->header(), pn + ".rfc822" );

        ++it;
    }

    d->fieldLookup =
        FieldNameCache::lookup( d->transaction, d->otherFields, this );
}


/*! This private function makes links in d->fieldLinks for each of the
    fields in \a hdr (from the bodypart numbered \a part). It is used
    by buildFieldLinks().
*/

void Injector::buildLinksForHeader( Header *hdr, const String &part )
{
    List< HeaderField >::Iterator it( hdr->fields()->first() );
    while ( it ) {
        HeaderField *hf = it;

        FieldLink *link = new FieldLink;
        link->hf = hf;
        link->part = part;

        if ( hf->type() >= HeaderField::Other )
            d->otherFields->append( new String ( hf->name() ) );

        d->fieldLinks->append( link );

        ++it;
    }
}


/*! This private function inserts an entry into bodyparts for every MIME
    bodypart in the message. The IDs are then stored in d->bodypartIds.
*/

void Injector::insertBodyparts()
{
    Query *i, *u, *s;
    Codec *c = new Utf8Codec;
    d->bodypartIds = new List< uint >;
    List< Query > *queries = new List< Query >;
    List< Query > *selects = new List< Query >;
    d->bidHelper = new IdHelper( d->bodypartIds, selects, this );

    List< Bodypart >::Iterator it( d->bodyparts->first() );
    while ( it ) {
        d->totalBodyparts++;
        Bodypart *b = it;
        ++it;

        bool text = true;
        bool data = true;

        ContentType *ct = b->contentType();
        if ( ct ) {
            if ( ct->type() != "text" )
                text = false;
            if ( ct->type() == "multipart" && ct->subtype() != "signed" )
                data = false;
            if ( ct->type() == "message" && ct->subtype() == "rfc822" )
                data = false;
        }

        String hash;
        if ( text )
            hash = MD5::hash( c->fromUnicode( b->text() ) ).hex();
        else
            hash = MD5::hash( b->data() ).hex();

        // This insert may fail if a bodypart with this hash already
        // exists. We don't care, as long as the select below works.
        i = new Query( *intoBodyparts, d->bidHelper );
        i->bind( 1, hash );
        i->bind( 2, b->numBytes() );
        // XXX: The next bit is wrong. Because of it, a text and a
        // non-text bodypart that have the same hash are stored
        // together, but this code stores text and non-text
        // differently.
        if ( text ) {
            i->bind( 3, c->fromUnicode( b->text() ), Query::Binary );
            i->bindNull( 4 );
        }
        else {
            i->bindNull( 3 );
            i->bind( 4, b->data(), Query::Binary );
        }
        queries->append( i );

        // Even if the insert fails, we may have to fix up the number of
        // lines in the table if a text bodypart is being shared with a
        // binary entry.
        if ( text ) {
            u = new Query( *fixBodypart, d->bidHelper );
            u->bind( 1, hash );
            u->bind( 2, b->numBytes() );
            queries->append( u );
        }

        s = new Query( *idBodypart, d->bidHelper );
        s->bind( 1, hash );
        queries->append( s );
        selects->append( s );
    }

    Database::submit( queries );
}


/*! This private function inserts one row per mailbox into the messages
    table.
*/

void Injector::insertMessages()
{
    Query *q;

    List< uint >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb;
        int uid = *uids;
        ++uids;
        ++mb;

        q = new Query( *intoMessages, 0 );
        q->bind( 1, m->id() );
        q->bind( 2, uid );
        q->bind( 3, d->idate );
        q->bind( 4, d->message->rfc822Size() );
        d->transaction->enqueue( q );

        q = new Query( *intoRecent, 0 );
        q->bind( 1, m->id() );
        q->bind( 2, uid );
        d->transaction->enqueue( q );
    }
}


/*! This private function inserts rows into the part_numbers table for
    each new message.
*/

void Injector::linkBodyparts()
{
    List< uint >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb;
        int uid = *uids;
        ++uids;
        ++mb;

        insertPartNumber( m->id(), uid, "", -1 );

        List< uint >::Iterator bids( d->bodypartIds->first() );
        List< Bodypart >::Iterator it( d->bodyparts->first() );
        while ( it ) {
            int bid = *bids;
            Bodypart *b = it;
            ++bids;
            ++it;

            String pn = d->message->partNumber( b );

            insertPartNumber( m->id(), uid, pn, bid );
            if ( b->rfc822() )
                insertPartNumber( m->id(), uid, pn + ".rfc822", bid );
        }
    }
}


/*! This private helper is used by linkBodyparts() to add a single row
    to part_numbers for \a mailbox, \a uid, \a part, and \a bodypart.
    If bodypart is smaller than 0, a NULL value is inserted instead.
*/

void Injector::insertPartNumber( int mailbox, int uid, const String &part,
                                 int bodypart )
{
    Query *q;

    q = new Query( *intoPartnumbers, 0 );
    q->bind( 1, mailbox );
    q->bind( 2, uid );
    q->bind( 3, part );
    if ( bodypart > 0 )
        q->bind( 4, bodypart );
    else
        q->bindNull( 4 );

    d->transaction->enqueue( q );
}


/*! This private function inserts entries into the header_fields table
    for each new message.
*/

void Injector::linkHeaderFields()
{
    Query *q;

    List< uint >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb;
        int uid = *uids;
        ++uids;
        ++mb;

        List< FieldLink >::Iterator it( d->fieldLinks->first() );
        while ( it ) {
            FieldLink *link = it;

            HeaderField::Type t = link->hf->type();
            if ( t >= HeaderField::Other )
                t = FieldNameCache::translate( link->hf->name() );

            q = new Query( *intoHeaderfields, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, link->part );
            q->bind( 4, t );
            q->bind( 5, link->hf->data() );

            d->transaction->enqueue( q );

            ++it;
        }
    }
}


/*! This private function inserts one entry per AddressLink into the
    address_fields table for each new message.
*/

void Injector::linkAddresses()
{
    Query *q;

    List< uint >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb;
        int uid = *uids;
        ++uids;
        ++mb;

        List< AddressLink >::Iterator it( d->addressLinks->first() );
        while ( it ) {
            AddressLink *link = it;

            q = new Query( *intoAddressfields, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, link->type );
            q->bind( 4, link->address->id() );

            d->transaction->enqueue( q );

            ++it;
        }
    }
}


/*! Logs information about the message to be injected. Some debug,
    some info.
*/

void Injector::logMessageDetails()
{
    String id;
    Header * h = d->message->header();
    if ( h )
        id = h->messageId();
    if ( id.isEmpty() ) {
        log( "Injecting message without message-id", Log::Debug );
        // should we log x-mailer? from? neither?
    }
    else {
        id = id + " ";
    }
    List<Mailbox>::Iterator it( d->mailboxes->first() );
    while ( it ) {
        log( "Injecting message " + id + "into mailbox " + it->name() );
        ++it;
    }
}


/*! This function announces the injection of a message into the relevant
    mailboxes, using ocd. It should be called only when the Injector has
    completed successfully (done(), but not failed()).

    The Mailbox objects in this process are notified immediately, to
    avoid timing-dependent behaviour within one process.
*/

void Injector::announce()
{
    List< Mailbox >::Iterator m( d->mailboxes->first() );
    List< uint >::Iterator u( d->uids->first() );
    while ( m ) {
        if ( m->uidnext() <= *u )
            m->setUidnext( 1 + *u );
        OCClient::send( "mailbox " + m->name().quoted() + " "
                        "message=" + fn( *u ) );
        ++m;
        ++u;
    }
}


/*! When the Injector injects a message into \a mailbox, it
    selects/learns the UID of the message. This function returns that
    UID. It returns 0 in case the message hasn't been inserted into
    \a mailbox, or if the uid isn't known yet.

    A nonzero return value does not imply that the injection is
    complete, or even that it will complete, only that injection has
    progressed far enough to select a UID.
*/

uint Injector::uid( Mailbox * mailbox ) const
{
    List<Mailbox>::Iterator m( d->mailboxes->first() );
    List<uint>::Iterator u( d->uids->first() );
    while ( m && u && m != mailbox ) {
        ++m;
        ++u;
    }
    if ( !u )
        return 0;
    return *u;
}
