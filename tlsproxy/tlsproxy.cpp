// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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


static CRYPT_SESSION cs;
static TlsProxy * userside;
static TlsProxy * serverside;


static String cryptlibError( int cryptError ) {
    String e;
    switch( cryptError ) {

    // The comments and strings below are copied from cryptlib.h (and
    // slightly modified).

    // Error in parameters passed to function
    case CRYPT_ERROR_PARAM1:
        e = "-1: CRYPT_ERROR_PARAM1: Bad argument, parameter 1";
        break;
    case CRYPT_ERROR_PARAM2:
        e = "-2: CRYPT_ERROR_PARAM2: Bad argument, parameter 2";
        break;
    case CRYPT_ERROR_PARAM3:
        e = "-3: CRYPT_ERROR_PARAM3: Bad argument, parameter 3";
        break;
    case CRYPT_ERROR_PARAM4:
        e = "-4: CRYPT_ERROR_PARAM4: Bad argument, parameter 4";
        break;
    case CRYPT_ERROR_PARAM5:
        e = "-5: CRYPT_ERROR_PARAM5: Bad argument, parameter 5";
        break;
    case CRYPT_ERROR_PARAM6:
        e = "-6: CRYPT_ERROR_PARAM6: Bad argument, parameter 6";
        break;
    case CRYPT_ERROR_PARAM7:
        e = "-7: CRYPT_ERROR_PARAM7: Bad argument, parameter 7";
        break;

    //Errors due to insufficient resources
    case CRYPT_ERROR_MEMORY:
        e = "-10: CRYPT_ERROR_MEMORY: Out of memory";
        break;
    case CRYPT_ERROR_NOTINITED:
        e = "-11: CRYPT_ERROR_NOTINITED: Data has not been initialised";
        break;
    case CRYPT_ERROR_INITED:
        e = "-12: CRYPT_ERROR_INITED: Data has already been init'd";
        break;
    case CRYPT_ERROR_NOSECURE:
        e = "-13: CRYPT_ERROR_NOSECURE: Opn.not avail.at requested sec.level";
        break;
    case CRYPT_ERROR_RANDOM:
        e = "-14: CRYPT_ERROR_RANDOM: No reliable random data available";
        break;
    case CRYPT_ERROR_FAILED:
        e = "-15: CRYPT_ERROR_FAILED: Operation failed";
        break;

    // Security violations
    case CRYPT_ERROR_NOTAVAIL:
        e = "-20:CRYPT_ERROR_NOTAVAIL: "
            "This type of opn.not available";
        break;
    case CRYPT_ERROR_PERMISSION:
        e = "-21:CRYPT_ERROR_PERMISSION: "
            "No permission to perform this operation";
        break;
    case CRYPT_ERROR_WRONGKEY:
        e = "-22:CRYPT_ERROR_WRONGKEY: "
            "Incorrect key used to decrypt data";
        break;
    case CRYPT_ERROR_INCOMPLETE:
        e = "-23:CRYPT_ERROR_INCOMPLETE: "
            "Operation incomplete/still in progress";
        break;
    case CRYPT_ERROR_COMPLETE:
        e = "-24: CRYPT_ERROR_COMPLETE: Operation complete/can't continue";
        break;
    case CRYPT_ERROR_TIMEOUT:
        e = "-25: CRYPT_ERROR_TIMEOUT: Operation timed out before completion";
        break;
    case CRYPT_ERROR_INVALID:
        e = "-26: CRYPT_ERROR_INVALID: Invalid/inconsistent information";
        break;
    case CRYPT_ERROR_SIGNALLED:
        e = "-27: CRYPT_ERROR_SIGNALLED: Resource destroyed by extnl.event";
        break;

    // High-level function errors
    case CRYPT_ERROR_OVERFLOW:
        e = "-30: CRYPT_ERROR_OVERFLOW: Resources/space exhausted";
        break;
    case CRYPT_ERROR_UNDERFLOW:
        e = "-31: CRYPT_ERROR_UNDERFLOW: Not enough data available";
        break;
    case CRYPT_ERROR_BADDATA:
        e = "-32: CRYPT_ERROR_BADDATA: Bad/unrecognised data format";
        break;
    case CRYPT_ERROR_SIGNATURE:
        e = "-33: CRYPT_ERROR_SIGNATURE: Signature/integrity check failed";
        break;

    // Data access function errors
    case CRYPT_ERROR_OPEN:
        e = "-40: CRYPT_ERROR_OPEN: Cannot open object";
        break;
    case CRYPT_ERROR_READ:
        e = "-41: CRYPT_ERROR_READ: Cannot read item from object";
        break;
    case CRYPT_ERROR_WRITE:
        e = "-42: CRYPT_ERROR_WRITE: Cannot write item to object";
        break;
    case CRYPT_ERROR_NOTFOUND:
        e = "-43: CRYPT_ERROR_NOTFOUND: Requested item not found in object";
        break;
    case CRYPT_ERROR_DUPLICATE:
        e = "-44: CRYPT_ERROR_DUPLICATE: Item already present in object";
        break;

    // Data enveloping errors
    case CRYPT_ENVELOPE_RESOURCE:
        e = "-50: CRYPT_ENVELOPE_RESOURCE: Need resource to proceed";
        break;

    // Should Not Happen[tm]
    default:
        e = fn( cryptError ) + ": Unknown error";
        break;
    }

    return e;
}


static String cryptlibLocus( int locus ) {
    String r = fn( locus );

    // there are so many attributes. too much work to specify them
    // all.
    return r;
}


static String cryptlibType( int type ) {
    String r = fn( type ) + ": ";
    switch( type ) {
    // The comments and strings below are copied from cryptlib.h (and
    // slightly modified).
    case CRYPT_ERRTYPE_NONE:
        r.append( "CRYPT_ERRTYPE_NONE: "
                  "No error information" );
        break;
    case CRYPT_ERRTYPE_ATTR_SIZE:
        r.append( "CRYPT_ERRTYPE_ATTR_SIZE: "
                  "Attribute data too small or large" );
        break;
    case CRYPT_ERRTYPE_ATTR_VALUE:
        r.append( "CRYPT_ERRTYPE_ATTR_VALUE: "
                  "Attribute value is invalid" );
        break;
    case CRYPT_ERRTYPE_ATTR_ABSENT:
        r.append( "CRYPT_ERRTYPE_ATTR_ABSENT: "
                  "Required attribute missing" );
        break;
    case CRYPT_ERRTYPE_ATTR_PRESENT:
        r.append( "CRYPT_ERRTYPE_ATTR_PRESENT: "
                  "Non-allowed attribute present" );
        break;
    case CRYPT_ERRTYPE_CONSTRAINT:
        r.append( "CRYPT_ERRTYPE_CONSTRAINT: "
                  "Cert: Constraint violation in object" );
        break;
    case CRYPT_ERRTYPE_ISSUERCONSTRAINT:
        r.append( "CRYPT_ERRTYPE_ISSUERCONSTRAINT: "
                  "Cert: Constraint viol.in issuing cert" );
        break;
    default:
        r.append( "Unknown error type" );
        break;
    }
    return r;
}


/* Logs \a cryptError suitably, or does nothing if its value is
   CRYPT_OK. \a function is the name of the cryptlib function which
   returned \a cryptError.
*/

static void handleError( int cryptError, const String & function )
{
    if ( cryptError == CRYPT_OK )
        return;

    if ( cryptStatusOK( cryptError ) )
        return;

    int locus = 0;
    int type = 0;
    cryptGetAttribute( cs, CRYPT_ATTRIBUTE_ERRORLOCUS, &locus );
    cryptGetAttribute( cs, CRYPT_ATTRIBUTE_ERRORTYPE, &type );

    String s = function + " reported error: " + cryptlibError( cryptError );
    if ( locus )
        s.append( ", locus: " + cryptlibLocus( locus ) );
    if ( type )
        s.append( ", type: " + cryptlibType( type ) );
    ::log( s, Log::Error );

    int errorStringLength;
    String errorString;
    errorString.reserve( 1024 );

    cryptGetAttributeString( cs, CRYPT_ATTRIBUTE_INT_ERRORMESSAGE,
                             (char*)errorString.data(), &errorStringLength );
    if ( errorStringLength > 1000 )
        exit( 0 ); // I'm too polite for the sort of comment needed here
    errorString.truncate( errorStringLength );

    errorString = errorString.simplified();
    if ( !errorString.isEmpty() > 0 )
        ::log( "cryptlib's own message: " + errorString );

    userside->close();
    serverside->close();

    Loop::shutdown();
}


static void setupCert()
{
    int status = 0;

    // Generate an RSA private key.
    CRYPT_CONTEXT privateKey;
    String label = "Mailstore on-demand key";

    status = cryptCreateContext( &privateKey, CRYPT_UNUSED, CRYPT_ALGO_RSA );
    handleError( status, "cryptGenerateKey" );
    status = cryptSetAttributeString( privateKey, CRYPT_CTXINFO_LABEL,
                                      label.cstr(), label.length() );
    handleError( status, "cryptSetAttributeString(LABEL)" );
    status = cryptGenerateKey( privateKey );
    handleError( status, "cryptGenerateKey" );

    // Save it to a keyset file.
    CRYPT_KEYSET keyset;
    status = cryptKeysetOpen( &keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                              "/tmp/keyset", CRYPT_KEYOPT_CREATE );
    handleError( status, "cryptKeysetOpen" );
    status = cryptAddPrivateKey( keyset, privateKey, "secret" );
    handleError( status, "cryptAddPrivateKey" );

    // Create a self-signed CA certificate.
    CRYPT_CERTIFICATE cert;
    String hostname = Configuration::hostname();

    status = cryptCreateCert( &cert, CRYPT_UNUSED, CRYPT_CERTTYPE_CERTIFICATE  );
    handleError( status, "cryptCreateCert" );
    /*status = cryptSetAttribute( cert, CRYPT_CERTINFO_XYZZY, 1 );
    handleError( status, "cryptSetAttribute" );*/
    CRYPT_CONTEXT publicKey;
    status = cryptGetPublicKey( keyset, &publicKey, CRYPT_KEYID_NAME,
                                label.cstr() );
    handleError( status, "cryptGetPublicKey" );
    status = cryptSetAttribute( cert, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
                                publicKey );
    handleError( status, "cryptSetAttribute(PUBLICKEYINFO)" );
    status = cryptSetAttribute( cert, CRYPT_CERTINFO_SELFSIGNED, 1 );
    handleError( status, "cryptSetAttribute(SELFSIGNED)" );
    status = cryptSetAttribute( cert, CRYPT_CERTINFO_CA, 1 );
    handleError( status, "cryptSetAttribute(CA)" );
    status = cryptSetAttributeString( cert, CRYPT_CERTINFO_COMMONNAME,
                                      hostname.cstr(), hostname.length() );
    handleError( status, "cryptSetAttribute(COMMONNAME)" );
    status = cryptSetAttribute( cert, CRYPT_CERTINFO_KEYUSAGE,
                                CRYPT_KEYUSAGE_DIGITALSIGNATURE |
                                CRYPT_KEYUSAGE_KEYCERTSIGN |
                                CRYPT_KEYUSAGE_KEYENCIPHERMENT );
    handleError( status, "cryptSetAttribute(KEYUSAGE)" );
    status = cryptSetAttribute( cert, CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
                                CRYPT_UNUSED );
    handleError( status, "cryptSetAttribute(EXTKEY)" );

    // Sign it with the private key and update the keyset.
    status = cryptSignCert( cert, privateKey );
    handleError( status, "cryptSignCert" );
    status = cryptAddPublicKey( keyset, cert );
    handleError( status, "cryptAddPublicKey" );

    // Clean up
    cryptKeysetClose( keyset );
    cryptDestroyCert( cert );
}


int main( int, char *[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    Server s( "tlsproxy" );
    s.setup( Server::Secure );
    // let cryptlib set up while still root, so it can read files etc.
    cryptInit();
    cryptAddRandom( NULL, CRYPT_RANDOM_SLOWPOLL );
    setupCert();
    Listener< TlsProxy >::create( "tlsproxy", "127.0.0.1", 2061 );
    // chroot and do the rest
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


/*!  Constructs an empty TlsProxy listening to \a socket.

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
    case Error:
    case Close:
        setState( Closing );
        if ( d->state != TlsProxyData::Initial ) {
            log( "Shutting down TLS proxy due to client close" );
            Loop::shutdown();
        }
        break;

    case Connect:
    case Shutdown:
        break;
    }
}


/*! Does nothing -- We want to allow cryptlib to read the data from this
    socket.
*/

void TlsProxy::read()
{
    if ( d->state != TlsProxyData::EncryptedSide )
        Connection::read();
}


/*! Parses the incoming request from other mailstore servers and
    starts setting up the TLS proxy. This Connection will be the
    encrypted one (user-side) and the other the plaintext
    (server-side) one.

    The syntax is a single line terminated by crlf. The line contains
    four space-separated fields: partner tag, protocol, client address
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
    List<TlsProxy>::Iterator it( proxies->first() );
    while ( other == 0 && it ) {
        TlsProxy * c = it;
        ++it;
        if ( c->d->key == tag )
            other = c;
    }
    if ( !other || other == this ) {
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
    Loop::flushAll();
    int p1 = fork();
    if ( p1 < 0 ) {
        // error
        log( "fork failed: " + fn( errno ) );
        setState( Closing );
        return;
    }
    else if ( p1 > 0 ) {
        // it's the parent
        Loop::removeConnection( this );
        Loop::removeConnection( other );
        close();
        other->close();
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
    Loop::closeAllExcept( this, other );
    enqueue( "ok\r\n" );
    write();
    log( "Starting TLS proxy for for " + protocol + " client " +
         client.string() + " (host " + Configuration::hostname() + ") (pid " +
         fn( getpid() ) + ")" );

    d->state = TlsProxyData::EncryptedSide;
    other->d->state = TlsProxyData::PlainSide;
    ::serverside = other;
    ::userside = this;

    int status;
    CRYPT_KEYSET keyset;
    CRYPT_CONTEXT privateKey;
    status = cryptKeysetOpen( &keyset, CRYPT_UNUSED, CRYPT_KEYSET_FILE,
                              "/tmp/keyset", CRYPT_KEYOPT_NONE );
    handleError( status, "cryptKeysetOpen" );
    status = cryptGetPrivateKey( keyset, &privateKey, CRYPT_KEYID_NAME,
                                 "Mailstore on-demand key", "secret" );
    handleError( status, "cryptGetPrivateKey" );
    status = cryptCreateSession( &cs, CRYPT_UNUSED, CRYPT_SESSION_SSL_SERVER );
    handleError( status, "cryptCreateSession" );
    userside->setBlocking( true );
    status = cryptSetAttribute( cs, CRYPT_SESSINFO_NETWORKSOCKET,
                                userside->fd() );
    handleError( status, "cryptSetAttribute(NETWORKSOCKET)" );
    status = cryptSetAttribute( cs, CRYPT_SESSINFO_VERSION, 1 );
    handleError( status, "cryptSetAttribute(VERSION)" );
    status = cryptSetAttribute( cs, CRYPT_SESSINFO_PRIVATEKEY, privateKey );
    handleError( status, "cryptSetAttribute(PRIVATEKEY)" );
    status = cryptSetAttribute( cs, CRYPT_SESSINFO_ACTIVE, 1 );
    handleError( status, "cryptSetAttribute(ACTIVE)" );
    cryptDestroyContext( privateKey );
    cryptKeysetClose( keyset );
}



/*! Encrypts and forwards the cleartext which is available on the socket. */

void TlsProxy::encrypt()
{
    Arena a;
    Scope b( &a );

    Buffer * r = readBuffer();
    String s = *r->string( r->size() );
    int len;
    int status = cryptPushData( cs, s.data(), s.length(), &len );
    handleError( status, "cryptPushData" );
    if ( status == CRYPT_OK ) {
        r->remove( len );
        status = cryptFlushData( cs );
        handleError( status, "cryptFlushData" );
    }
}


/*! Decrypts and forwards the ciphertext which is available on the socket. */

void TlsProxy::decrypt()
{
    Arena a;
    Scope b( &a );

    int status;
    int len;
    char buffer[4096];
    do {
        len = 0;
        status = cryptPopData( cs, buffer, 4096, &len );
        handleError( status, "cryptPopData" );
        if ( len > 0 )
            serverside->writeBuffer()->append( buffer, len );
    } while ( len > 0 && status == CRYPT_OK );
}
