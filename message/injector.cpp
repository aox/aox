#include "injector.h"

#include "message.h"
#include "mailbox.h"
#include "address.h"
#include "addressquery.h"
#include "dict.h"
#include "scope.h"


class InjectorData {
public:
    InjectorData();

    uint step;
    bool failed;

    const Message * message;
    List<Mailbox> * mailboxes;

    // working variables
    List<Address> * addresses;

    AddressQuery * addressQuery;
    Query * addressInsertion;
    Query * bodypartInsertion;
    Query * messageInsertion;

    EventHandler * owner;
};


InjectorData::InjectorData()
    : step( 0 ), failed( false ),
      message( 0 ), mailboxes( 0 ),
      addresses( new List<Address> ),
      addressQuery( 0 ), addressInsertion( 0 ),
      bodypartInsertion( 0 ), messageInsertion( 0 ),
      owner( 0 )
{
}


/*! \class Injector injector.h
  The Injector class performs all mail injection into the database.

  It assumes ownership of a single Message object, which is silently
  assumed to be valid, and does all necessary database operations to
  store this message.

  At present this class is more or less unusable, since it has no way
  of informing its caller/owner that it's done. That has to be fixed.
*/



/*! Constructs an Injector for \a message and immediately starts
    injecting the message into each of \a mailboxes concurrently. When
    injection is complete, Injector will call the
    EventHandler::execute() function of \a owner.

    Injector assumes ownership of \a mailboxes, so the caller may not
    delete or change the list.
*/

Injector::Injector( const Message * message, List<Mailbox> * mailboxes,
                    EventHandler * owner )
    : d( new InjectorData )
{
    d->mailboxes = mailboxes;
    d->message = message;
    d->owner = owner;
    execute();
}


/*! This is the gut function of Injector: It sets up a series of
    queries, one after another, to inject the message.
*/

void Injector::execute()
{
    if ( d->step == 0 ) {
        if ( d->addresses->isEmpty() )
            addAddresses();
        if ( !d->addressQuery )
            d->addressQuery = new AddressQuery( d->addresses, this );
        if ( d->addressQuery->done() )
            d->step = 1;
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


/*! Returns true if the injector has finished its work, and false if
    it hasn't started or is currently working.
*/

bool Injector::done() const
{
    return d->step >= 4;
}


/*! This private helper adds all the addresses in header fields of
    type \a t into the working list of addresses.
*/

void Injector::addAddresses( HeaderField::Type t )
{
    List<Address> * a = d->message->header()->addresses( t );
    if ( !a || a->isEmpty() )
        return;
    List<Address>::Iterator it( a->first() );
    while ( it != a->end() ) {
        d->addresses->append( it );
        ++it;
    }
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

    // now, hackily, make sure there are no repeated strings. this
    // is somehow wrong, because the domain is treated as if it
    // were case sensitive.
    List<Address>::Iterator it( d->addresses->first() );
    Dict<uint> tmp;
    uint hack;
    while ( it != d->addresses->end() ) {
        String k = (*it).toString();
        if ( tmp.contains( k ) ) {
            d->addresses->take( it );
        }
        else {
            tmp.insert( k, &hack );
            ++it;
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


/*! Returns true if injection has failed, and false if it has
    succeeded or is in progress.
*/

bool Injector::failed() const
{
    return d->failed;
}
