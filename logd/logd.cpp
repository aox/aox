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


File *logFile = 0;


/*! \nodoc */

int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Test::runTests();

    Configuration::makeGlobal( ".logdrc" );
    Configuration::Text logName( "logfile", "logfile" );

    (void)new SelfLogger;
    Log l( Log::Immediate );
    global.setLog( &l );

    logFile = new File( logName, File::Append );
    if ( !logFile->valid() ) {
        logFile = 0;
        log( Log::Error, "Could not open log file " + logName );
    }

    Listener< LogServer >::create( "Log Server", "", 2054 );

    log( Test::report() );
    Configuration::global()->report();

    Loop::start();
}
