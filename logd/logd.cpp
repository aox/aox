// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
    Scope global;

    Server s( "logd", argc, argv );
    s.setChrootMode( Server::LogDir );

    s.setup( Server::LogSetup );
    (void)new SelfLogger;
    String logName( Configuration::text( Configuration::LogFile ) );
    LogServer::setLogFile( logName );
    String logLevel( Configuration::text( Configuration::LogLevel ) );
    LogServer::setLogLevel( logLevel );

    s.setup( Server::Report );
    Listener< LogServer >::create( "log",
                                   Configuration::LogAddress,
                                   Configuration::LogPort );
    s.setup( Server::Finish );

    signal( SIGHUP, LogServer::reopen );

    s.execute();
}
