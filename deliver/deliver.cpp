#include "arena.h"
#include "scope.h"
#include "test.h"
#include "configuration.h"
#include "logclient.h"
#include "log.h"
#include "file.h"
#include "header.h"
#include "message.h"
#include "smtpclient.h"
#include "loop.h"

#include <stdlib.h>


/*! \nodoc */

int main( int argc, char *argv[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Configuration::setup( "mailstore.conf", "deliver.conf" );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    Configuration::report();

    File input( "/proc/self/fd/0", File::Read );
    String contents = input.contents();
    Message * m = new Message( contents, true );

    if ( !m || !m->valid() )
        exit( -1 );

    Address *a = m->header()->addresses( HeaderField::To )->first();
    (void)new SmtpClient( m, a );

    Loop::start();
}
