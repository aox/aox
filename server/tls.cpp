#include "tls.h"

#include "connection.h"
#include "string.h"
#include "configuration.h"
#include "buffer.h"
#include "event.h"
#include "log.h"


static Endpoint * tlsProxy = 0;


class TlsServerData
{
public:
    TlsServerData()
        : handler( 0 ),
          userside( 0 ), serverside( 0 ),
          done( false ), ok( false ) {}

    EventHandler * handler;

    class Client: public Connection
    {
    public:
        Client( TlsServerData * );
        void react( Event );
        void read( Event );

        class TlsServerData * d;

        String tag;
        bool done;
        bool ok;
    };

    Client * userside;
    Client * serverside;

    Endpoint client;
    String protocol;

    bool done;
    bool ok;
};


TlsServerData::Client::Client( TlsServerData * data )
    : Connection( Connection::connect( *tlsProxy ), Connection::Client ),
      d( data ), done( false ), ok( false )
{
}


void TlsServerData::Client::react( Event e )
{
    if ( e == Connect ) {
        return;
    }
    else if ( e != Read ) {
        done = true;
        d->handler->notify();
        return;
    }

    String * s = readBuffer()->removeLine();
    if ( !s )
        return;

    done = true;

    String l = s->simplified();
    if ( l.startsWith( "tlsproxy " ) ) {
        tag = l.mid( 9 );
        ok = true;
        if ( !d->serverside->ok || !d->userside->ok )
            return;

        d->userside->enqueue( d->serverside->tag + " " +
                              d->protocol + " " +
                              d->client.address() + " " +
                              String::fromNumber( d->client.port() ) +
                              "\r\n" );
    }
    else if ( l == "ok" ) {
        d->done = true;
        d->ok = true;
        d->handler->notify();
    }
}


/*! \class TlsServer tls.h
  The TlsServer class provides an interface to server-side TLS.

  On construction, it connects to a TlsProxy, and eventually verifies
  that the proxy is available to work as a server. Once its
  availability has been probed, done() returns true and ok() returns
  either a meaningful result.
*/


/*! Constructs a TlsServer and starts setting up the proxy server. It
    returns quickly, and later notifies \a handler when setup has
    completed. In the log files, the TlsServer will refer to \a client
    as client using \a protocol.
*/

TlsServer::TlsServer( EventHandler * handler, const Endpoint & client,
                      const String & protocol )
    : d( new TlsServerData )
{
    d->handler = handler;

    d->serverside = new TlsServerData::Client( d );
    d->userside = new TlsServerData::Client( d );

    d->protocol = protocol;
    d->client = client;
}


/*! Returns true if setup has finished, and false if it's still going on. */

bool TlsServer::done() const
{
    return d->done;
}


/*! Returns true if the TLS proxy is available for use, and false is
    an error happened or setup is still going on.
*/

bool TlsServer::ok() const
{
    return d->done && d->ok;
}


static bool tlsAvailable;


/*! Initializes the TLS subsystem. */

void TlsServer::setup()
{
    Configuration::Toggle atAll( "tls", true );
    ::tlsAvailable = atAll;
    if ( !tlsAvailable )
        return;

    Configuration::Text proxy( "tls-proxy-address", "127.0.0.1" );
    Configuration::Scalar port( "tls-proxy-port", 2061 );
    Endpoint * e = new Endpoint( proxy, port );
    if ( !e->valid() ) {
        log( Log::Error,
             "tls-proxy-address and/or tls-proxy-port is/are bad." );
        log( Log::Info, "TLS Support disabled" );
        return;
    }
    ::tlsAvailable = true;
    ::tlsProxy = e;
}


/*! Returns true if the server is convigured to support TLS, and false
    if it isn't, or if there's something wrong about the configuration.
*/

bool TlsServer::available()
{
    return ::tlsAvailable;
}


/*! Returns the Configuration to be used for the server (plaintext) side. */

Connection * TlsServer::serverSide() const
{
    return d->serverside;
}


/*! Returns the Connection to be used for the user (encrypted) side. */

Connection * TlsServer::userSide() const
{
    return d->userside;
}
