#include "arena.h"
#include "scope.h"
#include "event.h"
#include "string.h"
#include "configuration.h"
#include "smtpclient.h"
#include "logclient.h"
#include "file.h"
#include "loop.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>


static int status;
static SmtpClient *client;


int main( int argc, char *argv[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    String sender;
    String recipient;

    int n = 1;
    while ( n < argc ) {
        if ( argv[n][0] == '-' ) {
            switch ( argv[n][1] ) {
            case 'f':
                if ( argc - n > 1 )
                    sender = argv[++n];
                break;

            default:
                break;
            }
        }
        else {
            recipient = argv[n];
        }
        n++;
    }

    if ( sender == "" || recipient == "" ) {
        fprintf( stderr, "Syntax: deliver -f sender recipient ...\n" );
        exit( -1 );
    }

    Configuration::setup( "mailstore.conf", "deliver.conf" );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    Configuration::report();

    class DeliveryHelper : public EventHandler {
    public:
        void execute() {
            if ( client->failed() )
                status = -1;
            Loop::shutdown();
        }
    };

    File message( "/proc/self/fd/0", File::Read );
    client = new SmtpClient( sender, message.contents(), recipient,
                             new DeliveryHelper );
    Loop::start();
    return status;
}
