// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sieveaction.h"


class SieveActionData
    : public Garbage
{
public:
    SieveActionData()
        : type( SieveAction::FileInto ),
          mailbox( 0 ), address( 0 )
        {}

    SieveAction::Type type;
    Mailbox * mailbox;
    Address * address;
};


/*! \class SieveAction sieveaction.h

    The SieveAction class models a single sieve action as specified in
    RFC 3028 section 4, ie. something a SieveScript decides to do, and
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


/*! Records that this action's target is \a address, provided that its
    type() is Redirect. If type() has any other value, calling
    setAddress() sets an unused variable.
*/

void SieveAction::setAddress( Address * address )
{
    d->address = address;
}


/*! Returns the address set by setAddress(), or 0 if setAddress() has
    not been called. This value is only meaningful if type() is
    Redirect.
*/

Address * SieveAction::address() const
{
    return d->address;
}
