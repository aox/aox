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
#include "addressfield.h"
#include "addresscache.h"
#include "transaction.h"
#include "allocator.h"
#include "occlient.h"
#include "scope.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "html.h"


class IdHelper;


static PreparedStatement *lockUidnext;
static PreparedStatement *incrUidnext;
static PreparedStatement *idBodypart;
static PreparedStatement *intoBodyparts;


// These structs represent one part of each entry in the header_fields
// and address_fields tables. (The other part being mailbox and UID.)

struct FieldLink
    : public Garbage
{
    HeaderField *hf;
    String part;
    int position;
};

struct AddressLink
    : public Garbage
{
    Address * address;
    HeaderField::Type type;
    String part;
    int position;
};


// This struct contains the database IDs of Mailboxes or Bodyparts (we
// use only one struct because IdHelper has to process the results).
// Only one of the two pointers will be non-zero in one instance.

struct ObjectId
    : public Garbage
{
    ObjectId( Mailbox *m, Bodypart *b )
        : id( 0 ), mailbox( m ), bodypart( b )
    {}

    uint id;
    Mailbox *mailbox;
    Bodypart *bodypart;
};


class InjectorData
    : public Garbage
{
public:
    InjectorData()
        : step( 0 ), failed( false ),
          owner( 0 ), message( 0 ), transaction( 0 ),
          mailboxes( 0 ), bodyparts( 0 ),
          uidHelper( 0 ), bidHelper( 0 ),
          addressLinks( 0 ), fieldLinks( 0 ), otherFields( 0 ),
          fieldLookup( 0 ), addressLookup( 0 )
    {}

    int step;
    bool failed;

    EventHandler *owner;
    const Message *message;
    Transaction *transaction;

    // The *idHelpers fill in the IDs corresponding to each Object in
    // these lists.
    List< ObjectId > *mailboxes;
    List< ObjectId > *bodyparts;

    IdHelper *uidHelper;
    IdHelper *bidHelper;

    List< AddressLink > * addressLinks;
    List< FieldLink > * fieldLinks;
    List< String > * otherFields;

    CacheLookup * fieldLookup;
    CacheLookup * addressLookup;
};


class IdHelper : public EventHandler {
private:
    List< ObjectId >::Iterator *li;
    List< ObjectId > *list;
    List< Query > *queries;
    EventHandler *owner;

public:
    bool failed;

    IdHelper( List< ObjectId > *l, List< Query > *q, EventHandler *ev )
        : li( 0 ), list( l ), queries( q ), owner( ev ), failed( false )
    {}

    void execute() {
        Query *q;

        while ( ( q = queries->firstElement() ) != 0 &&
                q->done() )
        {
            queries->shift();

            if ( q->hasResults() ) {
                if ( !li )
                    li = new List< ObjectId >::Iterator( list );

                (*li)->id = q->nextRow()->getInt( 0u );
                ++(*li);
            }
            else {
                failed = true;
            }
        }

        if ( queries->isEmpty() )
            owner->execute();
    }

    bool done() const {
        return queries->isEmpty();
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

    intoBodyparts =
        new PreparedStatement(
            "insert into bodyparts (hash,bytes,text,data) "
            "values ($1,$2,$3,$4)"
        );
    Allocator::addEternal( intoBodyparts, "intoBodyparts" );
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

    d->mailboxes = new List< ObjectId >;
    SortedList< Mailbox >::Iterator mi( mailboxes );
    while ( mi ) {
        d->mailboxes->append( new ObjectId( mi, 0 ) );
        ++mi;
    }

    d->bodyparts = new List< ObjectId >;
    List< Bodypart >::Iterator bi( d->message->allBodyparts() );
    while ( bi ) {
        d->bodyparts->append( new ObjectId( 0, bi ) );
        ++bi;
    }
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


/*! Returns an error message if injection failed, or an empty string
    if it succeeded or hasn't failed yet.
*/

String Injector::error() const
{
    if ( !d->failed )
        return "";
    if ( !d->message->valid() )
        return d->message->error();
    if ( !d->transaction )
        return "";
    return d->transaction->error();
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
        if ( !d->message->valid() ) {
            d->failed = true;
            finish();
            return;
        }

        logMessageDetails();

        // We begin by obtaining a UID for each mailbox we are injecting
        // a message into, and simultaneously inserting entries into the
        // bodyparts table. At the same time, we can begin to lookup and
        // insert the addresses and field names used in the message.

        d->transaction = new Transaction( this );

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
        // messages.

        if ( !d->uidHelper->done() )
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

        if ( !d->fieldLookup->done() || !d->bidHelper->done() )
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
        finish();
    }
}


/*! This function notifies the owner of this Injector of its completion.
    It will do so only once.
*/

void Injector::finish()
{
    // XXX: If we fail early in the transaction, we'll continue to
    // be notified of individual query failures. We don't want to
    // pass them on, because d->owner would have killed itself.
    if ( d->owner ) {
        if ( d->failed )
            log( "Injection failed: " + error() );
        else
            log( "Injection succeeded" );
        d->owner->execute();
        d->owner = 0;
    }
}


/*! This private function issues queries to retrieve a UID for each of
    the Mailboxes we are delivering the message into, adds each UID to
    d->mailboxes, and informs execute() when it's done.
*/

void Injector::selectUids()
{
    Query *q;
    List< Query > * queries = new List< Query >;
    d->uidHelper = new IdHelper( d->mailboxes, queries, this );

    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        // We acquire a write lock on our mailbox, and hold it until the
        // entire transaction has committed successfully. We use uidnext
        // in lieu of a UID sequence to serialise Injectors, so that UID
        // announcements are correctly ordered.
        //
        // The mailbox list must be sorted, so that Injectors always try
        // to acquire locks in the same order, thus avoiding deadlocks.

        Mailbox *m = mi->mailbox;

        q = new Query( *lockUidnext, d->uidHelper );
        q->bind( 1, m->id() );
        d->transaction->enqueue( q );
        queries->append( q );

        q = new Query( *incrUidnext, d->uidHelper );
        q->bind( 1, m->id() );
        d->transaction->enqueue( q );

        ++mi;
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

    int i = 1;
    List< HeaderField >::Iterator it( d->message->header()->fields() );
    while ( it ) {
        HeaderField *hf = it;

        if ( hf->type() <= HeaderField::LastAddressField ) {
            List< Address > *al = ((AddressField *)hf)->addresses();
            if ( al && !al->isEmpty() ) {
                List< Address >::Iterator ai( al );
                while ( ai ) {
                    Address *a = ai;
                    String k = a->toString();

                    if ( unique.contains( k ) ) {
                        a = unique.find( k );
                    }
                    else {
                        unique.insert( k, a );
                        addresses->append( a );
                    }

                    AddressLink *link = new AddressLink;
                    link->part = "";
                    link->position = i;
                    link->type = hf->type();
                    link->address = a;
                    d->addressLinks->append( link );

                    ++ai;
                }
            }
        }

        ++it;
        i++;
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

    List< ObjectId >::Iterator bi( d->bodyparts );
    while ( bi ) {
        Bodypart *bp = bi->bodypart;

        String pn = d->message->partNumber( bp );

        if ( !skip )
            buildLinksForHeader( bp->header(), pn );
        else
            skip = false;

        if ( bp->message() )
            buildLinksForHeader( bp->message()->header(), pn + ".rfc822" );

        ++bi;
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
    int i = 1;
    List< HeaderField >::Iterator it( hdr->fields() );
    while ( it ) {
        HeaderField *hf = it;

        FieldLink *link = new FieldLink;
        link->hf = hf;
        link->part = part;
        link->position = i++;

        if ( hf->type() >= HeaderField::Other )
            d->otherFields->append( new String ( hf->name() ) );

        d->fieldLinks->append( link );

        ++it;
    }
}


/*! This private function inserts an entry into bodyparts for every MIME
    bodypart in the message. The IDs are then stored in d->bodyparts.
*/

void Injector::insertBodyparts()
{
    List< Query > *queries = new List< Query >;
    List< Query > *selects = new List< Query >;
    List< ObjectId > *insertedParts = new List< ObjectId >;
    d->bidHelper = new IdHelper( insertedParts, selects, this );

    List< ObjectId >::Iterator bi( d->bodyparts );
    while ( bi ) {
        Bodypart *b = bi->bodypart;

        // These decisions should move into Bodypart member functions.

        bool text = false;
        bool data = false;

        ContentType *ct = b->contentType();
        if ( ct ) {
            if ( ct->type() == "text" ) {
                text = true;
                if ( ct->subtype() == "html" )
                    data = true;
            }
            else {
                data = true;
                if ( ct->type() == "multipart" && ct->subtype() != "signed" )
                    data = false;
                if ( ct->type() == "message" && ct->subtype() == "rfc822" )
                    data = false;
            }
        }
        else {
            text = true;
        }

        if ( text || data ) {
            insertBodypart( b, data, text, queries, selects );
            insertedParts->append( bi );
        }

        ++bi;
    }

    Database::submit( queries );
}


/*! This private function inserts a row corresponding to \a b into the
    bodyparts table. If \a storeData is true, the contents are stored
    in the data column. If only \a storeText is true, the contents are
    stored in the text column instead. If they are both true, the data
    is stored in the data column, and a searchable representation is
    stored in the text column.

    It appends any queries it creates to \a queries, and appends the
    final id-select to \a selects.
*/

void Injector::insertBodypart( Bodypart *b,
                               bool storeData, bool storeText,
                               List< Query > *queries,
                               List< Query > *selects )
{
    Utf8Codec u;
    Query *i, *s;

    String data;
    if ( storeText )
        data = u.fromUnicode( b->text() );
    else if ( storeData )
        data = b->data();
    String hash = MD5::hash( data ).hex();

    // This insert may fail if a bodypart with this hash already
    // exists. We don't care, as long as the select below works.
    i = new Query( *intoBodyparts, d->bidHelper );
    i->bind( 1, hash );
    i->bind( 2, b->numBytes() );

    if ( storeText ) {
        String text( data );

        // This should also move into Bodypart::.
        if ( storeData )
            text = u.fromUnicode( HTML::asText( b->text() ) );

        i->bind( 3, text, Query::Binary );
    }
    else {
        i->bindNull( 3 );
    }

    if ( storeData )
        i->bind( 4, data, Query::Binary );
    else
        i->bindNull( 4 );

    i->allowFailure();
    queries->append( i );

    // XXX: The following query MUST be executed after the insert above.
    // But since they aren't inside the transaction, we can't be sure it
    // will be. Nor can we be sure that the row we just inserted wasn't
    // deleted along with bodyparts orphaned by EXPUNGE.
    s = new Query( *idBodypart, d->bidHelper );
    s->bind( 1, hash );
    queries->append( s );
    selects->append( s );
}


/*! This private function inserts one row per mailbox into the messages
    table.
*/

void Injector::insertMessages()
{
    Query *qm =
        new Query( "copy messages (mailbox,uid,idate,rfc822size) "
                   "from stdin with binary", 0 );

    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        uint uid = mi->id;
        Mailbox *m = mi->mailbox;

        qm->bind( 1, m->id(), Query::Binary );
        qm->bind( 2, uid, Query::Binary );
        qm->bind( 3, d->message->internalDate(), Query::Binary );
        qm->bind( 4, d->message->rfc822().length(), Query::Binary );
        qm->submitLine();

        ++mi;
    }

    d->transaction->enqueue( qm );
}


/*! This private function inserts rows into the part_numbers table for
    each new message.
*/

void Injector::linkBodyparts()
{
    Query *q =
        new Query( "copy part_numbers "
                   "(mailbox,uid,part,bodypart,bytes,lines) "
                   "from stdin with binary", 0 );

    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        uint uid = mi->id;
        Mailbox *m = mi->mailbox;

        insertPartNumber( q, m->id(), uid, "" );

        List< ObjectId >::Iterator bi( d->bodyparts );
        while ( bi ) {
            uint bid = bi->id;
            Bodypart *b = bi->bodypart;

            String pn = d->message->partNumber( b );
            insertPartNumber( q, m->id(), uid, pn, bid,
                              b->numEncodedBytes(),
                              b->numEncodedLines() );

            if ( b->message() )
                insertPartNumber( q, m->id(), uid, pn + ".rfc822",
                                  bid, b->numEncodedBytes(),
                                  b->numEncodedLines() );
            ++bi;
        }

        ++mi;
    }

    d->transaction->enqueue( q );
}


/*! This private helper is used by linkBodyparts() to add a single row
    of data to \a q for \a mailbox, \a uid, \a part, and \a bodypart.
    If bodypart is smaller than 0, a NULL value is inserted instead.
    If \a bytes and \a lines are greater than or equal to 0, their
    values are inserted along with the \a bodypart.
*/

void Injector::insertPartNumber( Query *q, int mailbox, int uid,
                                 const String &part, int bodypart,
                                 int bytes, int lines )
{
    q->bind( 1, mailbox, Query::Binary );
    q->bind( 2, uid, Query::Binary );
    q->bind( 3, part, Query::Binary );

    if ( bodypart > 0 )
        q->bind( 4, bodypart, Query::Binary );
    else
        q->bindNull( 4 );

    if ( bytes >= 0 )
        q->bind( 5, bytes, Query::Binary );
    else
        q->bindNull( 5 );

    if ( lines >= 0 )
        q->bind( 6, lines, Query::Binary );
    else
        q->bindNull( 6 );

    q->submitLine();
}


/*! This private function inserts entries into the header_fields table
    for each new message.
*/

void Injector::linkHeaderFields()
{
    Query *q =
        new Query( "copy header_fields "
                   "(mailbox,uid,part,position,field,value) "
                   "from stdin with binary", 0 );

    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        uint uid = mi->id;
        Mailbox *m = mi->mailbox;

        List< FieldLink >::Iterator it( d->fieldLinks );
        while ( it ) {
            FieldLink *link = it;

            HeaderField::Type t = link->hf->type();
            if ( t >= HeaderField::Other )
                t = FieldNameCache::translate( link->hf->name() );

            q->bind( 1, m->id(), Query::Binary );
            q->bind( 2, uid, Query::Binary );
            q->bind( 3, link->part, Query::Binary );
            q->bind( 4, link->position, Query::Binary );
            q->bind( 5, t, Query::Binary );
            q->bind( 6, link->hf->data(), Query::Binary );
            q->submitLine();

            ++it;
        }

        ++mi;
    }

    d->transaction->enqueue( q );
}


/*! This private function inserts one entry per AddressLink into the
    address_fields table for each new message.
*/

void Injector::linkAddresses()
{
    Query *q =
        new Query( "copy address_fields "
                   "(mailbox,uid,part,position,field,address) "
                   "from stdin with binary", 0 );

    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        uint uid = mi->id;
        Mailbox *m = mi->mailbox;

        List< AddressLink >::Iterator it( d->addressLinks );
        while ( it ) {
            AddressLink *link = it;

            q->bind( 1, m->id(), Query::Binary );
            q->bind( 2, uid, Query::Binary );
            q->bind( 3, link->part, Query::Binary );
            q->bind( 4, link->position, Query::Binary );
            q->bind( 5, link->type, Query::Binary );
            q->bind( 6, link->address->id(), Query::Binary );
            q->submitLine();

            ++it;
        }

        ++mi;
    }

    d->transaction->enqueue( q );
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

    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        log( "Injecting message " + id + "into mailbox " +
             mi->mailbox->name() );
        ++mi;
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
    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        uint uid = mi->id;
        Mailbox *m = mi->mailbox;

        if ( m->uidnext() <= uid ) {
            m->setUidnext( 1 + uid );
            OCClient::send( "mailbox " + m->name().quoted() + " "
                            "uidnext=" + fn( m->uidnext() ) );
        }

        ++mi;
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
    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi && mi->mailbox != mailbox )
        ++mi;
    if ( !mi )
        return 0;
    return mi->id;
}


/*! Returns a pointer to the Message to be/being/which was inserted,
    or a null pointer if this Injector isn't inserting exactly one
    Message.
*/

const Message * Injector::message() const
{
    return d->message;
}
