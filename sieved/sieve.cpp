// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieve.h"

#include "sieveaction.h"


class SieveData
    : public Garbage
{
public:
    SieveData()
        : sender( 0 ),
          currentRecipient( 0 ),
          message( 0 )
        {}

    class Recipient
        : public Garbage
    {
    public:
        Recipient( Address * a ): address( a ), done( false ), ok( true ) {}

        Address * address;
        bool done;
        bool ok;
        String result;
        List<SieveAction> actions;
    };
    Address * sender;
    List<Recipient> recipients;
    Recipient * currentRecipient;
    Message * message;

    Recipient * recipient( Address * a );
};


SieveData::Recipient * SieveData::recipient( Address * a )
{
    List<SieveData::Recipient>::Iterator it( recipients );
    while ( it && it->address != a )
        ++it;
    return it;
}


/*! \class Sieve sieve.h
  
    The Sieve class interprets the Sieve language, which processes
    incoming messages to determine their fate.

    The class requires fairly specific usage: An object is created,
    the message sender is set using setSender(), the recipients with
    addRecipient() and the message itself with setMessage().

    Once addRecipient() has been called, evaluate() may be, and can
    give results. It's unlikely (but possible) that results may be
    available before setMessage() has been called.
*/


/*! Constructs an empty message Sieve. */

Sieve::Sieve()
    : Garbage(), d( new SieveData )
{
    
}


/*! Records that the envelope sender is \a address. */

void Sieve::setSender( Address * address )
{
    d->sender = address;
}


/*! Records that \a address is one of the recipients for this
    message. If \a address is not a registered alias, Sieve will
    refuse mail to it.
*/

void Sieve::addRecipient( Address * address )
{
    d->recipients.append( new SieveData::Recipient( address ) );
    // XXX: start selecting a sieve script
    // XXX: select ... from aliases
}


/*! Records that \a message is to be used while sieving. All sieve
    tests that look at e.g. header fields look at \a message, and \a
    message is stored using fileinto/keep and forwarded using
    redirect.
*/

void Sieve::setMessage( Message * message )
{
    d->message = message;
}


/*! Returns a pointer to the address set with setSender(), or a null
    pointer if setSender() has not yet been called.
*/

Address * Sieve::sender() const
{
    return d->sender;
}


/*! Returns a pointe to the recipient currently being sieved, or a
    null pointer if the Sieve engine is not currently working on any
    particular recipient.

    In the future, I think we'll add a way to sieve between MAIL FROM
    and RCPT TO, so recipient() can realistically return 0.
*/

Address * Sieve::recipient() const
{
    if ( !d->currentRecipient )
        return 0;
    return d->currentRecipient->address;
}


/*! Runs any sieve scripts currently available, sees what results can
    be found, and returns when it can't do anything more. If done() is
    true after evaluate(), evaluate() need not be called again.
*/

void Sieve::evaluate()
{
    
}


/*! Returns true if delivery to \a address succeeded, and false if it
    failed or if evaluation is not yet complete.
*/

bool Sieve::succeeded( Address * address )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && i->ok;
    return false;
}


/*! Returns true if delivery to \a address failed or will fail, and
    false if it succeeded or if evaluation is not yet complete.
*/

bool Sieve::failed( Address * address )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->done && !i->ok;
    return false;
}


/*! Returns a single-line result string for use e.g. as SMTP/LMTP
    response. If neither failed() nor succeeded() returns true for \a
    address, the result of result() is undefined.
*/

String Sieve::result( Address * address )
{
    SieveData::Recipient * i = d->recipient( address );
    if ( i )
        return i->result;
    return "";
}


/*! Returns true if the Sieve has finished evaluation (although not
    execution), and false if there's more to do before evaluation is
    complete.
*/

bool Sieve::done() const
{
    List<SieveData::Recipient>::Iterator i( d->recipients );
    while ( i ) {
        if ( !i->done )
            return false;
        ++i;
    }
    return true;
}


/*! Records that \a action is to be performed if evaluation of the
    current user's sieve script does not fail.

    At some point, this may/will also do something of a more general
    nature if there is no current recipient. Global sieve scripts,
    etc.
*/

void Sieve::addAction( SieveAction * action )
{
    if ( d->currentRecipient )
        d->currentRecipient->actions.append( action );
}
