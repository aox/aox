#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "file.h"
#include "logserver.h"
#include "configuration.h"
#include "selflogger.h"
#include "server.h"


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );
    Server s( "logd" );

    s.setup( Server::Loop );

    (void)new SelfLogger;
    Configuration::Text logName( "logfile", Configuration::LogFile );
    LogServer::setLogFile( logName );

    s.setup( Server::Secure );

    Listener< LogServer >::create( "Log Server", "", 2054 );

    s.execute();
}
