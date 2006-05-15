// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievecommand.h"


class SieveCommandData
    : public Garbage
{
public:
    SieveCommandData() : type( SieveCommand::Action ) {}

    SieveCommand::Type type;
};


/*! \class SieveCommand sievecommand.h

    The SieveCommand is the superclass of all sieve command. At the
    moment that's just require, if and stop, and the various
    SieveAction commands. It seems likely that extensions will add
    more.

    SieveCommand itself models the three odds and ends. A subclass,
    SieveAction, models the actions, so that we can have a list/DAG of
    actions to perform after sieving.
*/  

/*!  Constructs a command of the required \a type. If \a type is
     Action, SieveAction::type() reveals the type of action.
*/

SieveCommand::SieveCommand( Type type )
    : Garbage(), d( new SieveCommandData )
{
    d->type = type;
}
