// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
    Configuration::Text logLevel( "loglevel", "info" );
    LogServer::setLogLevel( logLevel );

    Listener< LogServer >::create( "log", "127.0.0.1", 2054 );

    s.setup( Server::Secure );
    s.execute();
}
