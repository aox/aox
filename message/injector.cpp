#include "injector.h"

#include "arena.h"
#include "scope.h"
#include "dict.h"
#include "query.h"
#include "address.h"
#include "message.h"
#include "mailbox.h"
#include "addresscache.h"
#include "transaction.h"


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
        : step( 0 ), failed( false ),
          owner( 0 ), message( 0 ), mailboxes( 0 ), transaction( 0 ),
          totalUids( 0 ), uids( 0 ), totalBodyparts( 0 ), bodypartIds( 0 ),
          bodyparts( 0 ), addressLinks( 0 ), messageIds( 0 ),
          fieldLookup( 0 ), addressLookup( 0 )
    {}

    int step;
    bool failed;

    EventHandler * owner;
    const Message * message;
    List< Mailbox > * mailboxes;

    Transaction * transaction;

    uint totalUids;
    List< int > * uids;
    uint totalBodyparts;
    List< int > * bodypartIds;
    List< BodyPart > * bodyparts;
    List< AddressLink > * addressLinks;
    List< FieldLink > * fieldLinks;
    List< int > * messageIds;

    CacheLookup * fieldLookup;
    CacheLookup * addressLookup;
};


class IdHelper : public EventHandler {
private:
    List< int > * list;
    List< Query > * queries;
    EventHandler * owner;
public:
    IdHelper( List< int > *l, List< Query > *q, EventHandler *ev )
        : list( l ), queries( q ), owner( ev )
    {}

    void execute() {
        Query *q = queries->first();
        if ( !q->done() )
            return;

        list->append( q->nextRow()->getInt( "id" ) );

        queries->take( queries->first() );
        if ( queries->isEmpty() )
            owner->notify();
    }
};


/*! \class Injector injector.h
    This class delivers a Message to a List of Mailboxes.

    The Injector takes a Message object, and performs all the database
    operations necessary to inject it into each of a List of Mailboxes.
    The message is assumed to be valid.
*/

/*! Creates a new Injector object to deliver the \a message into each of
    the \a mailboxes on behalf of the \a owner, which is notified when
    the delivery attempt is completed. Message delivery commences when
    the execute() function is called.

    The caller must not change \a mailboxes after this call.
*/

Injector::Injector( const Message * message, List< Mailbox > * mailboxes,
                    EventHandler * owner )
    : d( new InjectorData )
{
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
    return d->step >= 4;
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
    if ( d->step == 0 ) {
        // We begin by obtaining a UID for each mailbox we are injecting
        // a message into, and simultaneously inserting entries into the
        // bodyparts table. At the same time, we can begin to lookup and
        // insert the addresses and field names used in the message.

        selectUids();
        insertBodyparts();
        updateAddresses();
        updateFieldNames();

        d->step = 1;
    }

    if ( d->step == 1 ) {
        // Once we have UIDs for each Mailbox, we can insert rows into
        // messages and recent_messages.

        if ( d->uids->count() != d->totalUids )
            return;

        insertMessages();
        d->step = 2;
    }

    if ( d->step == 2 ) {
        // We expect updateFieldNames() to have completed immediately.
        // Once insertBodyparts() is completed, we can start adding to
        // the header_fields and part_numbers tables.

        if ( !d->fieldLookup->done() ||
             d->bodypartIds->count() != d->totalBodyparts )
            return;

        linkHeaders();
        linkBodyparts();
        d->step = 3;
    }

    if ( d->step == 3 ) {
        // Fill in address_fields once the address lookup is complete.
        // (We could have done this without waiting for the bodyparts
        // to be inserted, but it didn't seem worthwhile.)

        if ( !d->addressLookup->done() )
            return;

        linkAddresses();
        d->step = 4;
    }

    if ( d->step == 4 ) {
        d->owner->notify();
    }
}


/*! This private function issues queries to retrieve a UID for each of
    the Mailboxes we are delivering the message into, adds each UID to
    d->uids, and informs execute() when it's done.
*/

void Injector::selectUids()
{
    d->uids = new List< int >;
    List< Query > * queries = new List< Query >;
    IdHelper * helper = new IdHelper( d->uids, queries, this );

    List< Mailbox >::Iterator it( d->mailboxes->first() );
    while ( it ) {
        d->totalUids++;
        String seq( "mailbox_" + String::fromNumber( it->id() ) );
        queries->append( new Query( "select nextval('"+seq+"')::integer as id",
                                    helper ) );
        it++;
    }

    Database::query( queries );
}


/*! This private function builds a list of AddressLinks containing every
    address used in the message, and initiates an AddressCache::lookup()
    after excluding any duplicate addresses. It causes execute() to be
    called when every address in d->addressLinks has been resolved.
*/

void Injector::updateAddresses()
{
    d->addressLinks = new List< AddressLink >;
    List< Address > * addresses = new List< Address >;
    Dict< Address > unique;

    HeaderField::Type types[] = {
        HeaderField::ReturnPath, HeaderField::Sender, HeaderField::ResentSender,
        HeaderField::From, HeaderField::To, HeaderField::Cc, HeaderField::Bcc,
        HeaderField::ResentFrom, HeaderField::ResentTo, HeaderField::ResentCc,
        HeaderField::ResentBcc, HeaderField::ReplyTo
    };
    int n = sizeof (types) / sizeof( types[0] );

    int i = 0;
    while ( i < n ) {
        HeaderField::Type t = types[ i++ ];
        List< Address > * a = d->message->header()->addresses( t );
        if ( a && !a->isEmpty() ) {
            List< Address >::Iterator it( a->first() );
            while ( it ) {
                Address *a = it++;
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
            }
        }
    }

    d->addressLookup = AddressCache::lookup( addresses, this );
}


/*! This private function builds a list of FieldLinks containing every
    header field used in the message, and uses FieldCache::lookup() to
    associate each unknown HeaderField with an ID. It causes execute()
    to be called when every field name in d->fieldLinks has been
    resolved.
*/

void Injector::updateFieldNames()
{
    d->fieldLinks = new List< FieldLink >;

    Header *h = d->message->header();
    HeaderField::Type types[] = {
        HeaderField::ReturnPath, HeaderField::From, HeaderField::To,
        HeaderField::Cc, HeaderField::Bcc, HeaderField::ReplyTo,
        HeaderField::Subject, HeaderField::Date, HeaderField::MessageId
    };
    int n = sizeof (types) / sizeof (types[0]);

    int i = 0;
    while ( i < n ) {
        HeaderField::Type t = types[ i++ ];

        FieldLink *link = new FieldLink;
        link->hf = h->field( t );
        link->part = "";

        if ( link->hf )
            d->fieldLinks->append( link );
    }

    // d->fieldLookup = FieldCache::lookup( fields, this );
    d->fieldLookup = new CacheLookup;
    d->fieldLookup->setState( CacheLookup::Completed );
}


/*! This private function inserts an entry into bodyparts for every MIME
    bodypart in the message. The IDs are then stored in d->bodypartIds.
*/

void Injector::insertBodyparts()
{
    d->bodypartIds = new List< int >;
    List< Query > * queries = new List< Query >;
    List< Query > * selects = new List< Query >;
    IdHelper * helper = new IdHelper( d->bodypartIds, selects, this );

    d->bodyparts = d->message->bodyParts();
    List< BodyPart >::Iterator it( d->bodyparts->first() );
    while ( it ) {
        d->totalBodyparts++;
        BodyPart *b = it++;

        Query *i, *s;

        i = new Query( "insert into bodyparts (data) values ($1)", helper );
        i->bind( 1, b->data(), Query::Binary );

        s = new Query( "select currval('bodypart_ids')::integer as id",
                       helper );

        queries->append( i );
        queries->append( s );
        selects->append( s );
    }

    Database::query( queries );
}


/*! This private function inserts one row per mailbox into the messages
    table, and puts the resulting ids in d->messageIds.
*/

void Injector::insertMessages()
{
    d->messageIds = new List< int >;
    List< Query > * queries = new List< Query >;
    List< Query > * selects = new List< Query >;
    IdHelper * helper = new IdHelper( d->messageIds, selects, this );

    List< int >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb++;
        int uid = *uids++;

        Query *i = new Query( "insert into messages (mailbox,uid) values "
                              "($1,$2)", helper );
        i->bind( 1, m->id() );
        i->bind( 2, uid );

        Query *i2 = new Query( "insert into recent_messages (mailbox,uid) "
                               "values ($1,$2)", helper );
        i2->bind( 1, m->id() );
        i2->bind( 2, uid );

        Query *s = new Query( "select currval('message_ids')::integer as id",
                              helper );

        queries->append( i );
        queries->append( i2 );
        queries->append( s );
        selects->append( s );
    }

    Database::query( queries );
}


/*! This private function inserts entries into the header_fields table
    for each new message.
*/

void Injector::linkHeaders()
{
    List< Query > *queries = new List< Query >;

    List< int >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb++;
        int uid = *uids++;

        List< FieldLink >::Iterator it( d->fieldLinks->first() );
        while ( it ) {
            FieldLink *link = it++;

            Query *q;
            q = new Query( "insert into header_fields "
                           "(mailbox,uid,part,field,value) values "
                           "($1,$2,$3,$4,$5)", 0 );
            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, link->part );
            q->bind( 4, link->hf->type() );
            q->bind( 5, link->hf->value() );

            queries->append( q );
        }
    }

    Database::query( queries );
}


/*! This private function inserts rows into the part_numbers table for
    each new message.
*/

void Injector::linkBodyparts()
{
    List< Query > * queries = new List< Query >;

    List< int >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb++;
        int uid = *uids++;

        List< int >::Iterator bids( d->bodypartIds->first() );
        List< BodyPart >::Iterator it( d->bodyparts->first() );
        while ( it ) {
            int bid = *bids++;
            BodyPart *b = it++;

            Query *q;
            q = new Query( "insert into part_numbers "
                           "(mailbox,uid,bodypart,partno) values "
                           "($1,$2,$3,$4)", 0 );
            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, bid );
            q->bind( 4, b->partNumber() );

            queries->append( q );
        }
    }

    Database::query( queries );
}


/*! This private function inserts one entry per AddressLink into the
    address_fields table for each new message.
*/

void Injector::linkAddresses()
{
    List< Query > *queries = new List< Query >;

    List< int >::Iterator uids( d->uids->first() );
    List< Mailbox >::Iterator mb( d->mailboxes->first() );
    while ( uids ) {
        Mailbox *m = mb++;
        int uid = *uids++;

        List< AddressLink >::Iterator it( d->addressLinks->first() );
        while ( it ) {
            AddressLink *link = it++;

            Query *q;
            q = new Query( "insert into address_fields "
                           "(mailbox,uid,field,address) values "
                           "($1,$2,$3,$4)", 0 );
            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, link->type );
            q->bind( 4, link->address->id() );

            queries->append( q );
        }
    }

    Database::query( queries );
}
