// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "file.h"
#include "scope.h"
#include "listener.h"
#include "logserver.h"
#include "configuration.h"
#include "selflogger.h"
#include "allocator.h"
#include "server.h"

#include <signal.h>


/*! \nodoc */

int main( int argc, char * argv[] )
{
    Scope global;

    Server s( "logd", argc, argv );
    s.setChrootMode( Server::LogDir );

    s.setup( Server::LogSetup );
    Allocator::addEternal( new SelfLogger, "the logger's logger" );

    EString logName( Configuration::text( Configuration::LogFile ) );
    EString logMode( Configuration::text( Configuration::LogfileMode ) );
    LogServer::setLogFile( logName, logMode );

    EString logLevel( Configuration::text( Configuration::LogLevel ) );
    LogServer::setLogLevel( logLevel );

    s.setup( Server::Report );
    Listener< LogServer >::create(
        "log", true,
        Configuration::LogAddress, Configuration::LogPort
    );
    s.setup( Server::Finish );

    signal( SIGHUP, LogServer::reopen );

    s.run();
}
