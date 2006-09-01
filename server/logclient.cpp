// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logclient.h"

#include "eventloop.h"
#include "string.h"
#include "server.h"
#include "connection.h"
#include "configuration.h"

// exit, perror
#include <stdlib.h>
// fprintf, stderr
#include <stdio.h>
// gettimeofday
#include <sys/time.h>
// localtime
#include <time.h>


/* This static function returns a nicely-formatted timestamp. */

static String time()
{
    struct timeval tv;
    struct timezone tz;
    if ( ::gettimeofday( &tv, &tz ) < 0 )
        return "";
    struct tm * t = localtime( (const time_t *)&tv.tv_sec );

    // yuck.
    char result[32];
    sprintf( result, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             t->tm_year + 1900, t->tm_mon+1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec,
             (int)tv.tv_usec/1000 );
    return result;
}


// This is our connection to the log server.
class LogClientData
    : public Connection
{
public:
    LogClientData( int fd, const Endpoint & e, Logger *client )
        : Connection( fd, Connection::LogClient ),
          logServer( e ), owner( client )
    {
    }

    ~LogClientData()
    {
        EventLoop::global()->removeConnection( this );
        delete owner;
        owner = 0;
    }

    void reconnect()
    {
        connect( logServer );
        EventLoop::global()->addConnection( this );
    }

    // The log server isn't supposed to send us anything.
    void react( Event e ) {
        switch ( e ) {
        case Connect:
        case Timeout:
            break;
        case Shutdown:
            if ( state() == Connected )
                enqueue( "shutdown\r\n" );
            break;
        case Read:
        case Close:
        case Error:
            delete owner;
            owner = 0;
            EventLoop::shutdown();
            break;
        }
    }

    Endpoint logServer;
    Logger *owner;
    String name;
};


/*! \class LogClient logclient.h
    A Logger subclass that talks to our log server. (LogdClient)

    This is the Logger that's used throughout most of the Oryx system.
    All programs that want to use the regular log server must call
    LogClient::setup() at startup.
*/

/*! Creates a new LogClient.  This constructor is usable only via
    setup().
*/

LogClient::LogClient()
    : Logger()
{
}


void LogClient::send( const String &id,
                      Log::Facility f, Log::Severity s,
                      const String & m )
{
    // We need to re-establish the connection to the log server after
    // the tlsproxy forks.
    if ( d->state() == Connection::Invalid )
        d->reconnect();

    String t( id );
    t.reserve( m.length() + 35 );
    t.append( " " );
    t.append( Log::facility( f ) );
    t.append( "/" );
    t.append( Log::severity( s ) );
    t.append( " " );
    t.append( time() );
    t.append( " " );
    t.append( m.simplified() );
    t.append( "\r\n" );
    d->enqueue( t );
    if ( d->state() == Connection::Connected )
        d->write();
}


/*! Connects to the configured log server and creates a singleton
    Logger named \a n talking to that server.

    If setup() cannot connect to a log server, it brutally exits the
    application.
*/

void LogClient::setup( const String & n )
{
    Endpoint e( Configuration::LogAddress, Configuration::LogPort );
    if ( !e.valid() ) {
        fprintf( stderr,
                 "%s: Unable to parse log server address %s:%d\n",
                 String(n).cstr(),
                 Configuration::text( Configuration::LogAddress ).cstr(),
                 Configuration::scalar( Configuration::LogPort ) );
        exit( -1 );
    }

    LogClient *client = new LogClient();
    client->d = new LogClientData( Connection::socket( e.protocol() ),
                                   e, client );
    client->d->name = n;
    client->d->setBlocking( true );
    if ( client->d->connect( e ) < 0 ) {
        fprintf( stderr, "%s: Unable to connect to log server %s\n",
                 client->name().cstr(), e.string().cstr() );
        exit( -1 );
    }
    client->d->setBlocking( false );
    client->d->enqueue( "name " + client->name() + "\r\n" );
    EventLoop::global()->addConnection( client->d );
}


/*! Returns the logclient's name, as set using setup(). */

String LogClient::name() const
{
    return d->name;
}
