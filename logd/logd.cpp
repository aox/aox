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
    s.setup( Server::Report );

    (void)new SelfLogger;
    Configuration::Text logName( "logfile", Configuration::LogFile );
    LogServer::setLogFile( logName );

    Listener< LogServer >::create( "log", "", 2054 );

    s.setup( Server::Secure );
    s.execute();
}
