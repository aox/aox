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


struct AddressLink {
    Address * address;
    HeaderField::Type type;
};


class InjectorData {
public:
    InjectorData()
        : step( 0 ), failed( false ),
          owner( 0 ), message( 0 ), mailboxes( 0 ), transaction( 0 ),
          uids( 0 ), bodyparts( 0 ), addressLinks( 0 )
    {}

    int step;
    bool failed;

    EventHandler * owner;
    const Message * message;
    List< Mailbox > * mailboxes;

    Transaction * transaction;

    List< int > * uids;
    List< int > * bodyparts;
    List< AddressLink > * addressLinks;
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


/*! Cleans up after injection. (We're pretty clean already.) */

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
        // a message into. At the same time, we can begin to look up and
        // insert addresses used in the message. We also start inserting
        // entries into the bodyparts table here.

        selectUids();
        updateAddresses();
        insertBodyparts();

        d->step = 1;
        return;
    }

    if ( d->step == 1 ) {
        d->step = 2;
    }

    if ( d->step == 2 ) {
        d->step = 3;
    }

    if ( d->step == 3 ) {
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
        String seq( "mailbox_" + String::fromNumber( it->id() ) );
        queries->append( new Query( "select nexval('"+seq+"')::integer as id",
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

    AddressCache::lookup( addresses, this );
}


/*! This private function inserts an entry into bodyparts for every MIME
    bodypart in the message, and puts the resulting ids in d->bodyparts.
*/

void Injector::insertBodyparts()
{
    d->bodyparts = new List< int >;
    List< Query > * queries = new List< Query >;
    List< Query > * selects = new List< Query >;
    IdHelper * helper = new IdHelper( d->bodyparts, selects, this );

    List< BodyPart > * bodyparts = d->message->bodyParts();
    List< BodyPart >::Iterator it( bodyparts->first() );
    while ( it ) {
        BodyPart *b = it++;

        Query *i, *s;

        i = new Query( "insert into bodyparts (data) values ($1)", helper );
        i->bind( 1, b->data() );

        s = new Query( "select currval('bodypart_ids')::integer as id",
                       helper );

        queries->append( i );
        queries->append( s );
        selects->append( s );
    }
}
