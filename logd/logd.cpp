#include "test.h"
#include "arena.h"
#include "scope.h"
#include "listener.h"
#include "file.h"
#include "loop.h"
#include "global.h"
#include "logserver.h"
#include "configuration.h"
#include "selflogger.h"


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::setup( "mailstore.conf", "logd.conf" );
    Configuration::Text logName( "logfile", Configuration::LogFile );

    Loop::setup();

    (void)new SelfLogger;
    Log l( Log::Immediate );
    global.setLog( &l );

    LogServer::setLogFile( logName );

    Listener< LogServer >::create( "Log Server", "", 2054 );

    log( Test::report() );
    Configuration::report();
    l.commit();

    Loop::start();
}
