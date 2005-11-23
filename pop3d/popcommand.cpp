// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "popcommand.h"


class PopCommandData
    : public Garbage
{
public:
    PopCommandData()
        : pop( 0 ), done( false )
    {}

    POP * pop;
    PopCommand::Command cmd;
    bool done;
};


/*! \class PopCommand popcommand.h
    This class represents a single POP3 command. It is analogous to an
    IMAP Command, except that it does all the work itself, rather than
    leaving it to subclasses.
*/


/*! Creates a new PopCommand object representing the command \a cmd, for
    the POP server \a pop.
*/

PopCommand::PopCommand( POP * pop, Command cmd )
    : d( new PopCommandData )
{
    d->pop = pop;
    d->cmd = cmd;
}


/*! Marks this command as having finished execute()-ing. Any responses
    are written to the client, and the POP server is instructed to move
    on to processing the next command.
*/

void PopCommand::finish()
{
    d->done = true;
    d->pop->write();
    d->pop->runCommands();
}


/*! Returns true if this PopCommand has finished executing, and false if
    execute() hasn't been called, or if it has work left to do. Once the
    work is done, execute() calls finish() to signal completion.
*/

bool PopCommand::done()
{
    return d->done;
}


void PopCommand::execute()
{
    switch ( d->cmd ) {
    case Quit:
        log( "Closing connection due to QUIT command", Log::Debug );
        d->pop->setState( POP::Update );
        d->pop->ok( "Goodbye" );
        break;

    case Capa:
        d->pop->ok( "Supported capabilities:" );
        d->pop->enqueue( "USER\r\n" );
        d->pop->enqueue( "RESP-CODES\r\n" );
        d->pop->enqueue( "PIPELINING\r\n" );
        d->pop->enqueue( "IMPLEMENTATION Oryx POP3 Server.\r\n" );
        d->pop->enqueue( ".\r\n" );
        break;

    case Noop:
        d->pop->ok( "Done" );
        break;
    }

    finish();
}
