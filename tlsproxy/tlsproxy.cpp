#include "arena.h"
#include "scope.h"
#include "configuration.h"
#include "logclient.h"
#include "listener.h"
#include "log.h"
#include "tlsproxy.h"
#include "server.h"
#include "occlient.h"
#include "entropy.h"
#include "buffer.h"
#include "list.h"

// cryptlib
#include "cryptlib.h"

// fork()
#include <sys/types.h>
#include <unistd.h>

// errno
#include <errno.h>

// exit()
#include <stdlib.h>


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "tlsproxy" );
    s.setup( Server::Report );
    LogClient::setup();
    s.setup( Server::Secure );
    Listener< TlsProxy >::create( "tls-proxy", "", 2061 );
    s.setup( Server::Finish );

    s.execute();
}



class TlsProxyData
{
public:
    TlsProxyData(): key( Entropy::asString( 9 ) ), state( Initial ) {}

    String key;
    enum State {
        Initial,
        PlainSide,
        EncryptedSide
    };
    State state;
};


static List<TlsProxy> * proxies = 0;


/*! \class TlsProxy tlsproxy.h
  The TlsProxy class provides half a tls proxy.

  It answers a request from another Mailstore server, hands out an
  identification number, and can build a complete proxy.

  The proxy needs two connections, one plaintext and one
  encrupted. Data comes in on one end, is encrypted/decrypted, is sent
  out on the other.
*/


/*!  Constructs an empty

*/

TlsProxy::TlsProxy( int socket )
    : Connection( socket, Connection::TlsProxy ), d( new TlsProxyData )
{
    Loop::addConnection( this );
    if ( !proxies )
        proxies = new List<TlsProxy>;
    proxies->append( this );

    enqueue( "tlsproxy " + d->key.e64() + "\r\n" );
}


/*! \reimp */

void TlsProxy::react( Event e )
{
    setTimeoutAfter( 1800 );

    switch ( e ) {
    case Read:
        switch( d->state ) {
        case TlsProxyData::Initial:
            parse();
            break;
        case TlsProxyData::PlainSide:
            encrypt();
            break;
        case TlsProxyData::EncryptedSide:
            decrypt();
            break;
        }
        break;

    case Timeout:
        enqueue( "Timeout\r\n" );
        log( "timeout" );
        setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
    case Shutdown:
        setState( Closing );
        break;
    }
}


/*! Parses the incoming request from other mailstore servers and
    starts setting up the TLS proxy. This Connection will be the
    plaintext (server-side) and the other the encrypted one
    (user-side) one.

    The syntax is a single line terminated by crlf. The line contains
    foud space-separated fields: partner tag, protocol, client address
    and client port.
*/

void TlsProxy::parse()
{
    String * l = readBuffer()->removeLine();
    if ( !l )
        return;
    String cmd = l->simplified();

    int i = cmd.find( ' ' );
    bool ok = true;
    if ( i <= 0 )
        ok = false;

    String tag = cmd.mid( 0, i ).de64();
    cmd = cmd.mid( i+1 );
    i = cmd.find( ' ' );
    if ( i <= 0 )
        ok = false;

    String proto = cmd.mid( 0, i );
    cmd = cmd.mid( i+1 );
    i = cmd.find( ' ' );
    if ( i <= 0 )
        ok = false;

    String addr = cmd.mid( 0, i );
    uint port = 0;
    if ( ok )
        port = cmd.mid( i+1 ).number( &ok );

    Endpoint client( addr, port );
    if ( !client.valid() )
        ok = false;

    if ( !ok ) {
        log( "syntax error: " + *l );
        setState( Closing );
        return;
    }

    TlsProxy * other = 0;
    List<TlsProxy>::Iterator it = proxies->first();
    while ( other == 0 && it != proxies->end() ) {
        TlsProxy * c = it;
        ++it;
        if ( c->d->key == tag )
            other = c;
    }
    if ( !other ) {
        log( "did not find partner" );
        setState( Closing );
        return;
    }

    start( other, client, proto );
}


/*! Starts TLS proxying with this object on the cleartext side and \a
    other on the encrypted side. \a client is logged as client using \a
    protocol.
*/

void TlsProxy::start( TlsProxy * other, const Endpoint & client, const String & protocol )
{
    int p1 = fork();
    if ( p1 < 0 ) {
        // error
        log( "fork failed: " + String::fromNumber( errno ) );
        setState( Closing );
        return;
    }
    else if ( p1 > 0 ) {
        // it's the parent
        Loop::removeConnection( this );
        Loop::removeConnection( other );
        delete other;
        delete this;
        return;
    }

    int p2 = fork();
    if ( p2 < 0 ) {
        // an error halfway through. hm. what to do?
        exit( 0 );
    }
    else if ( p2 > 0 ) {
        // it's the intermediate. it can exit.
        exit( 0 );
    }

    // it's the child!
    Loop::killAllExcept( this, other );
    enqueue( "ok\r\n" );
    LogClient::setup();
    log( "Starting TLS proxy for for " + protocol + " client " +
         client.string() + " (host " + Configuration::hostname() + ") (pid " +
         String::fromNumber( getpid() ) + ")" );

    d->state = TlsProxyData::PlainSide;
    other->d->state = TlsProxyData::EncryptedSide;
}


/*! Encrypts and forwards the cleartext which is available on the socket. */

void TlsProxy::encrypt()
{

}


/*! Decrypts and forwards the ciphertext which is available on the socket. */

void TlsProxy::decrypt()
{

}
