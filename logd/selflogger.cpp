#include "selflogger.h"

#include "logserver.h"

/*! \class SelfLogger selflogger.h

    The SelfLogger class logs messages directly, without network
    access, using the LogServer that is its alter ego.

    It exists primarily so that the log server process can call log
    before it has set up its sockets to read log information from
    others.
*/


/*!  Constructs a SelfLogger logging and a log server to help it. */

SelfLogger::SelfLogger()
    : Logger(), ls( new LogServer() )
{
}


void SelfLogger::send( const String & s )
{
    ls->processLine( s );
}
