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
    String filename;
    bool error = false;

    int n = 1;
    while ( n < argc ) {
        if ( argv[n][0] == '-' ) {
            switch ( argv[n][1] ) {
            case 'f':
                if ( argc - n > 1 )
                    sender = argv[++n];
                break;

            default:
                error = true;
                break;
            }
        }
        else if ( recipient.isEmpty() ) {
            recipient = argv[n];
        }
        else if ( filename.isEmpty() ) {
            filename = argv[n];
        }
        else {
            error = true;
        }
        n++;
    }

    if ( error || recipient.isEmpty() ) {
        fprintf( stderr,
                 "Syntax: deliver [ -f sender ] recipient [ filename ]\n" );
        exit( -1 );
    }

    // ### teach File to read from stdin properly
    if ( filename.isEmpty() )
        filename = "/proc/self/fd/0";

    File message( filename, File::Read );
    if ( !message.valid() ) {
        fprintf( stderr, "Unable to open message file %s\n", filename.cstr() );
        exit( -1 );
    }

    String contents = message.contents();

    if ( sender.isEmpty() && 
         ( contents.startsWith( "From " ) ||
           contents.startsWith( "Return-Path:" ) ) ) {
        uint i = contents.find( '\n' );
        if ( i < 0 ) {
            fprintf( stderr, "Message contains no LF\n" );
            exit( -2 );
        }
        sender = contents.mid( 0, i );
        contents = contents.mid( i+1 );
        if ( sender[0] == 'R' )
            i = sender.find( ':' );
        else
            i = sender.find( ' ' );
        sender = sender.mid( i+1 ).simplified();
            i = sender.find( ' ' );
        if ( i > 0 )
            sender.truncate( i );
        if ( sender.startsWith( "<" ) && sender.endsWith( ">" ) )
            sender = sender.mid( 1, sender.length()-2 );
    }

    fprintf( stderr, "Using recipient %s and sender %s\n",
             recipient.cstr(), sender.cstr() );
    
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

    client = new SmtpClient( sender, contents, recipient,
                             new DeliveryHelper );
    Loop::start();
    return status;
}
