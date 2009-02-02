// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieveaction.h"

#include "ustring.h"
#include "estring.h"


class SieveActionData
    : public Garbage
{
public:
    SieveActionData()
        : type( SieveAction::FileInto ),
          mailbox( 0 ), sender( 0 ), recipient( 0 ), message( 0 ),
          expiry( 0 )
        {}

    SieveAction::Type type;
    Mailbox * mailbox;
    Address * sender;
    Address * recipient;
    Injectee * message;
    UString handle;
    EString errorMessage;
    uint expiry;
};


/*! \class SieveAction sieveaction.h

    The SieveAction class models a single sieve action as specified in
    RFC 5228 section 4, ie. something a SieveScript decides to do, and
    that the Sieve interpreter does after sieving a message.

    SieveAction objects are created by SieveCommand objects while
    evaluating themselves in the context of a Message.
*/



/*! Constructs a SieveAction of \a type. The constructed object is not
    immediately valid; depending on \a type you may have to call
    e.g. setMailbox().
*/

SieveAction::SieveAction( Type type )
    : Garbage(), d( new SieveActionData )
{
    d->type = type;
}


/*! Returns the action's type, as set by the constructor. */

SieveAction::Type SieveAction::type() const
{
    return d->type;
}


/*! Records that this action's target is \a mailbox, provided that its
    type() is FileInto. If type() has any other value, calling
    setMailbox() sets an unused variable.
*/

void SieveAction::setMailbox( Mailbox * mailbox )
{
    d->mailbox = mailbox;
}


/*! Returns the mailbox set by setMailbox(), or 0 if setMailbox() has
    not been called. This value is only meaningful if type() is
    FileInto.
*/

Mailbox * SieveAction::mailbox() const
{
    return d->mailbox;
}


/*! Records that this action's sender target is \a address, provided
    that its type() is Redirect or Vacation. If type() has any other
    value, calling setSenderAddress() sets an unused variable.
*/

void SieveAction::setSenderAddress( Address * address )
{
    d->sender = address;
}


/*! Returns the address set by setSenderAddress(), or 0 if
    setSenderAddress() has not been called.
*/

Address * SieveAction::senderAddress() const
{
    return d->sender;
}


/*! Records that this action's recipient is \a address, provided that
    its type() is Redirect or Vacation. If type() has any other value,
    calling setRecipientAddress() sets an unused variable.
*/

void SieveAction::setRecipientAddress( Address * address )
{
    d->recipient = address;
}


/*! Returns the address set by setRecipientAddress(), or 0 if
    setRecipientAddress() has not been called.
*/

Address * SieveAction::recipientAddress() const
{
    return d->recipient;
}


/*! Returns true if this action has finished its task, and false
    otherwise.
*/

bool SieveAction::done() const
{
    if ( failed() )
        return true;
    return false;
}


/*! Returns true if this action has failed to accomplish its task, and
    false if it has succeeded or the possibility of success remains.
*/

bool SieveAction::failed() const
{
    return false;
}


/*! Records the error message \a m. Only useful if the action's type()
    is Error.
*/

void SieveAction::setErrorMessage( const EString & m )
{
    d->errorMessage = m;
}


/*! Returns what setErrorMessage() recorded, or an empty string if
    setErrorMessage() has not been called.
*/

EString SieveAction::errorMessage() const
{
    return d->errorMessage;
}


/*! Records that the handle associated with this action is \a h. Only
    useful for the Vacation type().
*/

void SieveAction::setHandle( const UString & h )
{
    d->handle = h;
}


/*! Returns whatever setHandle() set, or an empty string if
    setHandle() hasn't been called.
*/

UString SieveAction::handle() const
{
    return d->handle;
}


/*! Records that \a m is associated with this action. Only useful when
    type() is Vacation.
*/

void SieveAction::setMessage( Injectee * m )
{
    d->message = m;
}


/*! Returns whatever setMessage() recorded, or a null pointer if
    setMessage() hasn't been called.
*/

Injectee * SieveAction::message() const
{
    return d->message;
}


/*! Records that this autoresponse should suppress similar
    autoresponses for \a n days. Similarity is defined by handle(),
    recipientAddress() and senderAddress().
*/

void SieveAction::setExpiry( uint n )
{
    d->expiry = n;
}


/*! Returns whatever setExpiry() recorded, or 0 if setExpiry() hasn't
    been called.
*/

uint SieveAction::expiry() const
{
    return d->expiry;
}
