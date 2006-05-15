// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievecommand.h"


class SieveCommandData
    : public Garbage
{
public:
    SieveCommandData()
        : type( SieveCommand::Keep ),
          mailbox( 0 ), address( 0 )
        {}

    SieveCommand::Type type;
    Mailbox * mailbox;
    Address * address;
};


/*! \class SieveCommand sievecommand.h

    The SieveCommand models all sieve commands. At the moment that's
    just require, if and stop, and the various sieve action
    commands. It seems likely that extensions will add more.

    A SieveCommand object lives in a SieveScript, or possibly in an if
    which is in turn part of a SieveScript. When evaluate() is called,
    it considers a Message in the context of itself and generates some
    SieveAction objects as appropriate.
*/  

/*!  Constructs a command of the required \a type. If \a type is
     Action, SieveAction::type() reveals the type of action.
*/

SieveCommand::SieveCommand( Type type )
    : Garbage(), d( new SieveCommandData )
{
    d->type = type;
}


/*! Returns the action's type, as set by the constructor. */

SieveCommand::Type SieveCommand::type() const
{
    return d->type;
}


/*! Records that this action's target is \a mailbox, provided that its
    type() is FileInto. If type() has any other value, calling
    setMailbox() sets an unused variable.
*/

void SieveCommand::setMailbox( Mailbox * mailbox )
{
    d->mailbox = mailbox;
}


/*! Returns the mailbox set by setMailbox(), or 0 if setMailbox() has
    not been called. This value is only meaningful if type() is
    FileInto.
*/

Mailbox * SieveCommand::mailbox() const
{
    return d->mailbox;
}


/*! Records that this action's target is \a address, provided that its
    type() is Redirect. If type() has any other value, calling
    setAddress() sets an unused variable.
*/

void SieveCommand::setAddress( Address * address )
{
    d->address = address;
}


/*! Returns the address set by setAddress(), or 0 if setAddress() has
    not been called. This value is only meaningful if type() is
    Redirect.
*/

Address * SieveCommand::address() const
{
    return d->address;
}
