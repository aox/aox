// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "file.h"
#include "logserver.h"
#include "configuration.h"
#include "selflogger.h"
#include "server.h"

#include <signal.h>


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "logd", argc, argv );
    s.setChrootMode( Server::LogDir );

    s.setup( Server::LogSetup );
    (void)new SelfLogger;
    Configuration::Text logName( "logfile", Configuration::LogFile );
    LogServer::setLogFile( logName );
    Configuration::Text logLevel( "loglevel", "info" );
    LogServer::setLogLevel( logLevel );

    s.setup( Server::Report );
    Listener< LogServer >::create( "log", "127.0.0.1", 2054 );
    s.setup( Server::Finish );

    signal( SIGHUP, LogServer::reopen );

    s.execute();
}
