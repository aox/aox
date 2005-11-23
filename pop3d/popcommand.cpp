// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "popcommand.h"


class PopCommandData
    : public Garbage
{
public:
    PopCommandData() {}
};


/*! \class PopCommand popcommand.h
    This class represents a single POP3 command. It is analogous to an
    IMAP Command, except that it does all the work itself, rather than
    leaving it to subclasses.
*/


/*! Creates a new PopCommand object. */

PopCommand::PopCommand()
    : d( new PopCommandData )
{
}


void PopCommand::execute()
{
}
