// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "scope.h"
#include "event.h"
#include "string.h"
#include "allocator.h"
#include "configuration.h"
#include "smtpclient.h"
#include "logclient.h"
#include "file.h"
#include "eventloop.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>

// time, ctime
#include <time.h>


class Deliverator
    : public EventHandler
{
public:
    String sender, contents, recipient;
    SmtpClient *client;
    const char *errstr;
    int status;

    Deliverator( const String &s, const String &c, const String &r )
        : sender( s ), contents( c ), recipient( r ),
          client( 0 ), errstr( 0 ), status( 0 )
    {
        Allocator::addEternal( this, "deliver object" );
        client = new SmtpClient( sender, contents, recipient,
                                 this );
    }

    virtual ~Deliverator() {}

    void execute() {
        if ( client->failed() ) {
            errstr = client->error().cstr();
            status = -1;
        }
        EventLoop::shutdown();
    }
};


int main( int argc, char *argv[] )
{
    Scope global;

    String sender;
    String recipient;
    String filename;
    bool error = false;
    int verbose = 0;

    int n = 1;
    while ( n < argc ) {
        if ( argv[n][0] == '-' ) {
            switch ( argv[n][1] ) {
            case 'f':
                if ( argc - n > 1 )
                    sender = argv[++n];
                break;

            case 'v':
                {
                    int i = 1;
                    while ( argv[n][i] == 'v' ) {
                        verbose++;
                        i++;
                    }
                    if ( argv[n][i] != '\0' )
                        error = true;
                }
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
                 "Syntax: deliver [-v] [-f sender] recipient [filename]\n" );
        exit( -1 );
    }

    File message( filename );
    if ( !message.valid() ) {
        fprintf( stderr, "Unable to open message file %s\n", filename.cstr() );
        exit( -1 );
    }

    Configuration::setup( "archiveopteryx.conf" );

    String contents = message.contents();

    if ( sender.isEmpty() &&
         ( contents.startsWith( "From " ) ||
           contents.startsWith( "Return-Path:" ) ) ) {
        int i = contents.find( '\n' );
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
        if ( sender.find( '@' ) < 0 )
            sender = sender + "@" + Configuration::hostname();
    }

    if ( verbose > 0 )
        fprintf( stderr, "Sending to <%s> from <%s>\n",
                 recipient.cstr(), sender.cstr() );

    EventLoop::setup();
    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "delivery log" );
    global.setLog( l );
    LogClient::setup( "deliver" );

    Configuration::report();
    Deliverator *d = new Deliverator( sender, contents, recipient );
    Allocator::addEternal( d, "delivery object" );
    EventLoop::global()->start();

    if ( verbose > 0 && d->status < 0 ) {
        fprintf( stderr, "Error: %s\n", d->errstr );

        if ( verbose > 1 ) {
            File f( "/tmp/delivery.errors", File::Append );
            if ( f.valid() ) {
                time_t t = time(0);
                f.write( "From " + d->sender + " " + ctime(&t) );
                f.write( d->contents + "\n" );
            }
        }
    }

    return d->status;
}
