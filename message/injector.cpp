#include "injector.h"

#include "arena.h"
#include "scope.h"
#include "dict.h"
#include "address.h"
#include "message.h"
#include "mailbox.h"
#include "addresscache.h"
#include "transaction.h"


class InjectorData {
public:
    InjectorData()
        : message( 0 ), mailboxes( 0 ), owner( 0 ),
          step( 0 ), failed( false ), transaction( 0 ),
          addresses( new List< Address > )
    {}

    const Message * message;
    List< Mailbox > * mailboxes;
    EventHandler * owner;

    uint step;
    bool failed;

    Transaction * transaction;

    List< Address > * addresses;
};


/*! \class Injector injector.h
    This class is responsible for injecting mail into the database.

    It assumes ownership of a single Message object, which is silently
    assumed to be valid, and does all necessary database operations to
    store this message.
*/

/*! Creates a new Injector object to deliver the \a message into each of
    the \a mailboxes on behalf of the \a owner, which is notified when
    the delivery attempt is completed. Message delivery commences when
    the execute() function is called.

    The caller must not change \a mailboxes.
*/

Injector::Injector( const Message * message, List< Mailbox > * mailboxes,
                    EventHandler * owner )
    : d( new InjectorData )
{
    d->mailboxes = mailboxes;
    d->message = message;
    d->owner = owner;
    setArena( Scope::current()->arena() );
}


/*! Cleans up after injection. (We're pretty clean already.) */

Injector::~Injector()
{
}


/*! This function creates and executes the series of database queries
    needed to perform message delivery.
*/

void Injector::execute()
{
    if ( d->step == 0 ) {
        addAddresses();
        AddressCache::lookup( d->addresses, this );
        d->step = 1;
    }
    if ( d->step == 1 ) {
        int remaining = 0;

        List< Address >::Iterator it( d->addresses->first() );
        while ( it ) {
            if ( it->id() == 0 )
                remaining++;
            it++;
        }

        if ( remaining == 0 )
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


/*! This private helper adds all the addresses in header fields of
    type \a t into the working list of addresses.
*/

void Injector::addAddresses( HeaderField::Type t )
{
    List< Address > * a = d->message->header()->addresses( t );
    if ( !a || a->isEmpty() )
        return;

    List< Address >::Iterator it( a->first() );
    while ( it )
        d->addresses->append( it++ );
}


/*! This private helper makes a list of addresses used in the message,
    for inserting into the database.
*/

void Injector::addAddresses()
{
    addAddresses( HeaderField::From );
    addAddresses( HeaderField::ResentFrom );
    addAddresses( HeaderField::Sender );
    addAddresses( HeaderField::ResentSender );
    addAddresses( HeaderField::ReturnPath );
    addAddresses( HeaderField::ReplyTo );
    addAddresses( HeaderField::To );
    addAddresses( HeaderField::Cc );
    addAddresses( HeaderField::Bcc );
    addAddresses( HeaderField::ResentTo );
    addAddresses( HeaderField::ResentCc );
    addAddresses( HeaderField::ResentBcc );

    // Remove repeated addresses from the list, hackily.
    // (XXX: This wrongly treats the domain as case-sensitive.)

    uint hack;
    Dict< uint > tmp;
    List< Address >::Iterator it( d->addresses->first() );
    while ( it ) {
        String k = it->toString();

        if ( tmp.contains( k ) ) {
            d->addresses->take( it );
        }
        else {
            tmp.insert( k, &hack );
            it++;
        }
    }
}



#if 0

void Injector::execute()
{
    if ( d->step == 0 ) {
    }
    if ( d->step == 1 ) {
        String q = addressQuery();
        if ( q.isEmpty() )
            d->step = 2;
        else {
            if ( !d->addressInsertion )
                d->addressInsertion = new Query( q, this );
            if ( d->addressInsertion->done() ) {
                // having injected, we step back to start to fetch the
                // IDs we just injected.
                d->step = 0;
                d->addressInsertion = 0;
                d->addressQuery = 0;
            }
        }
    }
    if ( d->step == 2 ) {
        if ( !d->messageInsertion )
            d->messageInsertion = new Query( messageQuery(), this );
        if ( d->messageInsertion->done() )
            d->step = 3;
    }
    if ( d->step == 3 ) {
        if ( !d->bodypartInsertion )
            d->bodypartInsertion = new Query( bodypartQuery(), this );
        if ( d->bodypartInsertion->done() )
            d->step = 4;
    }
    if ( d->step == 4 ) {
        if ( d->owner ) {
            Scope tmp ( d->owner->arena() );
            d->owner->execute();
        }
    }
}


static String insertString( Address * a )
{
    String r( "insert into addresses (name,localpart,domain) values ('" );
    r.append( a->name().quoted( '\'', '\'' ) );
    r.append( "','" );
    r.append( a->localpart().quoted( '\'', '\'' ) );
    r.append( "','" );
    r.append( a->domain().quoted( '\'', '\'' ) );
    r.append( "')" );
    return r;
}


/*! This private helper returns a long string suitable to inject all
    the uncached addresses into the addresses table. If there are no
    uncached addresses, it returns an empty string.
*/

String Injector::addressQuery() const
{
    String q;
    List<Address>::Iterator it( d->addresses->first() );
    while ( it != d->addresses->end() ) {
        Address * a = it;
        ++it;
        if ( a->id() == 0 ) {
            if ( !q.isEmpty() )
                q.append( ";" );
            q.append( insertString( a ) );
        }
    }
    return q;
}


/*! This private helper returns a string suitable to inject the
    message's body into the bodyparts table. This is a big problem -
    the bodyparts table needs an ID for the messages table, and where
    do we get that?
*/

String Injector::bodypartQuery() const
{
    return "insert into bodyparts(message,partno)"
        " values "
        " (XXX,'1')";
}


/*! This private helper returns a string suitable to inject the
    message into the messages table.
*/

String Injector::messageQuery() const
{
    String r = "insert into messages(sender,returnpath,subject,messageid)"
               " values (";
    Header * h = d->message->header();
    Address * a = h->addresses( HeaderField::Sender )->first();
    r.append( String::fromNumber( a->id() ) );
    r.append( "," );
    a = h->addresses( HeaderField::ReturnPath )->first();
    r.append( String::fromNumber( a->id() ) );
    r.append( ",'" );
    r.append( h->field( HeaderField::Subject )->value().quoted( '\'', '\'' ) );
    r.append( "','" );
    r.append( h->messageId().quoted( '\'', '\'' ) );
    r.append( "')" );
    return r;
}

#endif
