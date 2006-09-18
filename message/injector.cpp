// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "injector.h"

#include "dict.h"
#include "flag.h"
#include "query.h"
#include "address.h"
#include "message.h"
#include "ustring.h"
#include "mailbox.h"
#include "bodypart.h"
#include "datefield.h"
#include "mimefields.h"
#include "fieldcache.h"
#include "addressfield.h"
#include "addresscache.h"
#include "transaction.h"
#include "annotation.h"
#include "allocator.h"
#include "occlient.h"
#include "scope.h"
#include "html.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "dsn.h"


class IdHelper;


static PreparedStatement *lockUidnext;
static PreparedStatement *incrUidnext;
static PreparedStatement *idBodypart;
static PreparedStatement *intoBodyparts;
static PreparedStatement *insertFlag;
static PreparedStatement *insertAnnotation;


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
        : state( Injector::Inactive ), failed( false ),
          owner( 0 ), message( 0 ), transaction( 0 ),
          beforeTransaction( 0 ),
          mailboxes( 0 ), bodyparts( 0 ),
          uidHelper( 0 ), bidHelper( 0 ),
          addressLinks( 0 ), fieldLinks( 0 ), dateLinks( 0 ),
          otherFields( 0 ), fieldLookup( 0 ), addressLookup( 0 )
    {}

    Injector::State state;

    bool failed;

    EventHandler *owner;
    Message *message;
    Transaction *transaction;
    List<Query> * beforeTransaction;

    // The *idHelpers fill in the IDs corresponding to each Object in
    // these lists.
    List< ObjectId > *mailboxes;
    List< ObjectId > *bodyparts;

    IdHelper *uidHelper;
    IdHelper *bidHelper;

    List< AddressLink > * addressLinks;
    List< FieldLink > * fieldLinks;
    List< FieldLink > * dateLinks;
    List< String > * otherFields;

    CacheLookup * fieldLookup;
    CacheLookup * addressLookup;

    class Flag
        : public Garbage
    {
    public:
        Flag( const String & n ): name( n ), flag( 0 ) {}
        String name;
        ::Flag * flag;
    };

    List<Flag> flags;
    List<Annotation> annotations;
};


class IdHelper : public EventHandler {
public:
    List< ObjectId >::Iterator *li;
    List< ObjectId > *list;
    List< Query > *queries;
    List< Query > *inserts;
    EventHandler *owner;
    bool failed;
    String error;

    IdHelper( List< ObjectId > *l, List< Query > *q, EventHandler *ev )
        : li( 0 ), list( l ), queries( q ), inserts( 0 ), owner( ev ),
          failed( false )
    {}

    void execute() {
        Query *q;

        while ( ( q = queries->firstElement() ) != 0 &&
                q->done() )
        {
            queries->shift();

            Query * insert = 0;
            if ( inserts )
                insert = inserts->shift();

            if ( q->hasResults() ) {
                if ( !li )
                    li = new List< ObjectId >::Iterator( list );

                (*li)->id = q->nextRow()->getInt( 0u );
                ++(*li);
            }
            else {
                failed = true;
                if ( insert )
                    error = insert->error();
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

    insertFlag =
        new PreparedStatement(
            "insert into flags (flag,uid,mailbox) "
            "values ($1,$2,$3)"
        );
    Allocator::addEternal( insertFlag, "insertFlag" );

    insertAnnotation =
        new PreparedStatement(
            "insert into annotations (mailbox,uid,name,value,owner) "
            "values ($1,$2,$3,$4,$5)"
        );
    Allocator::addEternal( insertAnnotation, "insertAnnotation" );
}


/*! Creates a new Injector to deliver the \a message on behalf of
    the \a owner, which is notified when the injection is completed.
    Message delivery commences when the execute() function is called.

    The caller must call setMailbox() or setMailboxes() to tell the
    Injector where to deliver the message.
*/

Injector::Injector( Message * message, EventHandler * owner )
    : d( new InjectorData )
{
    if ( !lockUidnext )
        setup();
    d->owner = owner;
    d->message = message;

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


/*! Instructs this Injector to deliver the message to the list of
    Mailboxes specified in \a m.
*/

void Injector::setMailboxes( SortedList<Mailbox> * m )
{
    d->mailboxes = new List< ObjectId >;
    SortedList<Mailbox>::Iterator mi( m );
    while ( mi ) {
        d->mailboxes->append( new ObjectId( mi, 0 ) );
        ++mi;
    }
}


/*! This function is provided for the convenience of the callers who
    only ever need to specify a single target Mailbox \a m.
*/

void Injector::setMailbox( Mailbox * m )
{
    SortedList<Mailbox> * l = new SortedList<Mailbox>;
    l->insert( m );
    setMailboxes( l );
}


/*! Instructs the Injector to set the specified IMAP \a flags on the
    newly injected message. If this function is not called, no flags
    will be set.
*/

void Injector::setFlags( const StringList & flags )
{
    Dict<void> uniq;
    StringList::Iterator fi( flags );
    while ( fi ) {
        if ( !uniq.contains( fi->lower() ) ) {
            d->flags.append( new InjectorData::Flag( *fi ) );
            uniq.insert( fi->lower(), (void*) 1 );
        }
        ++fi;
    }
}


/*! Instructs the Injector to create the specified IMAP \a annotations
    on the newly injected message. If this function is not called, no
    annotations will be created.
*/

void Injector::setAnnotations( const List<Annotation> * annotations )
{
    List<Annotation>::Iterator it( annotations );
    while ( it ) {
        Annotation * a = it;

        List<Annotation>::Iterator at( d->annotations );
        while ( at &&
                ( at->ownerId() != a->ownerId() ||
                  at->entryName()->name() != a->entryName()->name() ) )
            ++at;

        if ( at )
            at->setValue( a->value() );
        else
            d->annotations.append( a );

        ++it;
    }
}


/*! Returns true if this injector has finished its work, and false if it
    hasn't started or is currently working.
*/

bool Injector::done() const
{
    return ( d->failed || d->state == Done );
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
    if ( d->bidHelper->failed )
        return d->bidHelper->error;
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

    if ( d->state == Inactive ) {
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

        // The bodyparts inserts happen outside d->transaction, the
        // concomitant selects go inside.
        insertBodyparts();
        createFlags();
        createAnnotationNames();

        d->state = InsertingBodyparts;
    }

    if ( d->state == InsertingBodyparts ) {
        // Wait for all queries that have to be run before the
        // transaction to complete, then start the transaction.
        List<Query>::Iterator i( d->beforeTransaction );
        while ( i && i->done() )
            ++i;
        if ( i )
            return;

        selectUids();
        buildAddressLinks();
        buildFieldLinks();
        d->transaction->execute();

        d->state = SelectingUids;
    }

    if ( d->state == SelectingUids && !d->transaction->failed() ) {
        // Once we have UIDs for each Mailbox, we can insert rows into
        // messages.

        if ( !d->uidHelper->done() )
            return;

        insertMessages();

        d->transaction->execute();
        d->state = InsertingMessages;
    }

    if ( d->state == InsertingMessages && !d->transaction->failed() ) {
        if ( d->bidHelper->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
    }

    if ( d->state == InsertingMessages && !d->transaction->failed() ) {
        // We expect buildFieldLinks() to have completed immediately.
        // Once we have the bodypart IDs, we can start adding to the
        // part_numbers, header_fields, and date_fields tables.

        if ( !d->fieldLookup->done() || !d->bidHelper->done() )
            return;

        linkBodyparts();
        linkHeaderFields();
        linkDates();

        d->transaction->execute();
        d->state = LinkingFields;
    }

    if ( d->state == LinkingFields && !d->transaction->failed() ) {
        // Fill in address_fields once the address lookup is complete.
        // (We could have done this without waiting for the bodyparts
        // to be inserted, but it didn't seem worthwhile.)

        if ( !d->addressLookup->done() )
            return;

        linkAddresses();
        d->state = LinkingFlags;
    }

    if ( d->state == LinkingFlags ) {
        List<InjectorData::Flag>::Iterator i( d->flags );
        while ( i ) {
            if ( !i->flag )
                i->flag = Flag::find( i->name );
            if ( !i->flag )
                return;
            ++i;
        }
        linkFlags();
        d->state = LinkingAnnotations;
    }

    if ( d->state == LinkingAnnotations ) {
        List<Annotation>::Iterator i( d->annotations );
        while ( i ) {
            if ( i->entryName()->id() == 0 ) {
                AnnotationName * n;
                n = AnnotationName::find( i->entryName()->name() );
                if ( n->id() != 0 )
                    i->setEntryName( n );
            }
            if ( i->entryName()->id() == 0 )
                return;
            ++i;
        }
        linkAnnotations();
        d->state = LinkingAddresses;
    }

    if ( d->state == LinkingAddresses || d->transaction->failed() ) {
        // Now we just wait for everything to finish.
        if ( d->state < AwaitingCompletion )
            d->transaction->commit();
        d->state = AwaitingCompletion;
    }

    if ( d->state == AwaitingCompletion ) {
        if ( !d->transaction->done() )
            return;
        if ( !d->failed )
            d->failed = d->transaction->failed();
        d->state = Done;
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
    if ( !d->owner )
        return;

    if ( d->failed )
        log( "Injection failed: " + error() );
    else
        log( "Injection succeeded" );
    d->owner->execute();
    d->owner = 0;
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
    d->dateLinks = new List< FieldLink >;
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

        if ( part.isEmpty() && hf->type() == HeaderField::Date )
            d->dateLinks->append( link );

        ++it;
    }
}


/*! This private function inserts an entry into bodyparts for every MIME
    bodypart in the message. The IDs are then stored in d->bodyparts.
*/

void Injector::insertBodyparts()
{
    d->beforeTransaction = new List<Query>;
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
            insertBodypart( b, data, text, selects );
            insertedParts->append( bi );
        }

        ++bi;
    }

    d->bidHelper->inserts = d->beforeTransaction;
}


/*! This private function inserts a row corresponding to \a b into the
    bodyparts table. If \a storeData is true, the contents are stored
    in the data column. If only \a storeText is true, the contents are
    stored in the text column instead. If they are both true, the data
    is stored in the data column, and a searchable representation is
    stored in the text column.

    It appends any queries it creates to d->beforeTransaction, and
    appends the id-select to \a selects.
*/

void Injector::insertBodypart( Bodypart *b,
                               bool storeData, bool storeText,
                               List< Query > * selects )
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
    i = new Query( *intoBodyparts, this );
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
    d->beforeTransaction->append( i );
    i->execute();

    s = new Query( *idBodypart, d->bidHelper );
    s->bind( 1, hash );
    selects->append( s );
    d->transaction->enqueue( s );
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

    // XXX this may be much too slow. Crab, could you look at whether
    // COPY would work faster?
    const char * s = "insert into modsequences (mailbox,uid,modseq) "
                     "values ($1,$2,nextval('nextmodsequence'))";
    mi = d->mailboxes->first();
    while ( mi ) {
        Query * q = new Query( s, 0 );
        q->bind( 1, mi->mailbox->id() );
        q->bind( 2, mi->id );
        d->transaction->enqueue( q );
        ++mi;
        s = "insert into modsequences (mailbox,uid,modseq) "
            "values ($1,$2,currval('nextmodsequence'))";
    }
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


/*! This private function inserts entries into the date_fields table
    for each new message.
*/

void Injector::linkDates()
{
    List< ObjectId >::Iterator mi( d->mailboxes );
    while ( mi ) {
        uint uid = mi->id;
        Mailbox *m = mi->mailbox;

        List< FieldLink >::Iterator it( d->dateLinks );
        while ( it ) {
            FieldLink * link = it;
            DateField * df = (DateField *)link->hf;

            Query *q =
                new Query( "insert into date_fields (mailbox,uid,value) "
                           "values ($1,$2,$3)", 0 );

            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, df->date()->imap() );

            d->transaction->enqueue( q );

            ++it;
        }

        ++mi;
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

Message * Injector::message() const
{
    return d->message;
}


/*! Starts creating Flag objects for the flags we need to store for
    this message.
*/

void Injector::createFlags()
{
    StringList unknown;
    List<InjectorData::Flag>::Iterator it( d->flags );
    while ( it ) {
        it->flag = Flag::find( it->name );
        if ( !it->flag )
            unknown.append( it->name );
        ++it;
    }

    if ( !unknown.isEmpty() )
        (void)new FlagCreator( this, unknown );
}


/*! Creates the AnnotationName objects needed to create the annotation
    entries specified with setAnnotations().
*/

void Injector::createAnnotationNames()
{
    StringList unknown;
    List<Annotation>::Iterator it( d->annotations );
    while ( it ) {
        if ( !it->entryName()->id() )
            unknown.append( it->entryName()->name() );
        ++it;
    }

    if ( !unknown.isEmpty() )
        (void)new AnnotationNameCreator( this, unknown );
}


/*! Inserts the flag table entries linking flag_names to the
    mailboxes/uids we occupy.
*/

void Injector::linkFlags()
{
    List<InjectorData::Flag>::Iterator i( d->flags );
    while ( i ) {
        List<ObjectId>::Iterator m( d->mailboxes );
        while ( m ) {
            Query * q = new Query( *insertFlag, this );
            q->bind( 1, i->flag->id() );
            q->bind( 2, m->id );
            q->bind( 3, m->mailbox->id() );
            d->transaction->enqueue( q );
            ++m;
        }
        ++i;
    }
}


/*! Inserts the appropriate entries into the annotations table. */

void Injector::linkAnnotations()
{
    List<Annotation>::Iterator it( d->annotations );
    while ( it ) {
        List<ObjectId>::Iterator m( d->mailboxes );
        while ( m ) {
            Query * q = new Query( *insertAnnotation, this );
            q->bind( 1, m->mailbox->id() );
            q->bind( 2, m->id );
            q->bind( 3, it->entryName()->id() );
            q->bind( 4, it->value() );
            if ( it->ownerId() == 0 )
                q->bindNull( 5 );
            else
                q->bind( 5, it->ownerId() );
            d->transaction->enqueue( q );
            ++m;
        }
        ++it;
    }
}


/*! Returns a pointer to a SortedList of the mailboxes that this
    Injector was instructed to deliver to with setMailboxes().
*/

SortedList<Mailbox> * Injector::mailboxes() const
{
    SortedList<Mailbox> * mailboxes = new SortedList<Mailbox>;
    List<ObjectId>::Iterator it( d->mailboxes );
    while ( it ) {
        mailboxes->append( it->mailbox );
        ++it;
    }

    return mailboxes;
}
