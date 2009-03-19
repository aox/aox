// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logclient.h"

#include "eventloop.h"
#include "estring.h"
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
// openlog, syslog
#include <syslog.h>


/* This static function returns a nicely-formatted timestamp. */

static EString time()
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
    EString name;
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
    : Logger(), d( 0 ), useSyslog( false )
{
}


void LogClient::send( const EString &id, Log::Severity s, const EString & m )
{
    if ( useSyslog ) {
        uint sp = LOG_DEBUG;
        switch ( s ) {
        case Log::Debug:
            sp = LOG_DEBUG;
            break;
        case Log::Info:
            sp = LOG_INFO;
            break;
        case Log::Significant:
            sp = LOG_NOTICE;
            break;
        case Log::Error:
            sp = LOG_ERR;
            break;
        case Log::Disaster:
            sp = LOG_ALERT; // or _EMERG?
            break;
        }
        ::syslog( sp, "%s %s", id.cstr(), m.cstr() );
        return;
    }

    // We need to re-establish the connection to the log server after
    // the tlsproxy forks.
    if ( d->state() == Connection::Invalid )
        d->reconnect();

    EString t( id );
    t.reserve( m.length() + 35 );
    t.append( " x/" );
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

void LogClient::setup( const EString & n )
{
    Endpoint e( Configuration::LogAddress, Configuration::LogPort );
    if ( !e.valid() ) {
        fprintf( stderr,
                 "%s: Unable to parse log server address %s:%d\n",
                 EString(n).cstr(),
                 Configuration::text( Configuration::LogAddress ).cstr(),
                 Configuration::scalar( Configuration::LogPort ) );
        exit( -1 );
    }

    EString logName( Configuration::text( Configuration::LogFile ) );
    LogClient * client = new LogClient();
    if ( logName.startsWith( "syslog/" ) ) {
        client->useSyslog = true;
        EString f = logName.section( "/", 2 ).lower();
        uint sfc = LOG_LOCAL7;
        if ( f == "auth" )
            sfc = LOG_AUTH;
        else if ( f == "authpriv" )
            sfc = LOG_AUTHPRIV;
        else if ( f == "cron" )
            sfc = LOG_CRON;
        else if ( f == "daemon" )
            sfc = LOG_DAEMON;
        else if ( f == "ftp" )
            sfc = LOG_FTP;
        else if ( f == "kern" )
            sfc = LOG_KERN;
        else if ( f == "lpr" )
            sfc = LOG_LPR;
        else if ( f == "mail" )
            sfc = LOG_MAIL;
        else if ( f == "news" )
            sfc = LOG_NEWS;
        else if ( f == "syslog" )
            sfc = LOG_SYSLOG;
        else if ( f == "user" )
            sfc = LOG_USER;
        else if ( f == "uucp" )
            sfc = LOG_UUCP;
        else if ( f == "local0" )
            sfc = LOG_LOCAL0;
        else if ( f == "local1" )
            sfc = LOG_LOCAL1;
        else if ( f == "local2" )
            sfc = LOG_LOCAL2;
        else if ( f == "local3" )
            sfc = LOG_LOCAL3;
        else if ( f == "local4" )
            sfc = LOG_LOCAL4;
        else if ( f == "local5" )
            sfc = LOG_LOCAL5;
        else if ( f == "local6" )
            sfc = LOG_LOCAL6;
        else if ( f == "local7" )
            sfc = LOG_LOCAL7;
        else {
            fprintf( stderr, "%s: Unknown syslog facility: %s\n",
                     EString(n).cstr(), f.cstr() );
            exit( -1 );
        }
        openlog( "Archiveopteryx", LOG_CONS|LOG_NDELAY, sfc );
    }
    else {
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
}


/*! Returns the logclient's name, as set using setup(). */

EString LogClient::name() const
{
    return d->name;
}
