#include "arena.h"
#include "scope.h"
#include "configuration.h"
#include "connection.h"
#include "logclient.h"
#include "listener.h"
#include "loop.h"
#include "log.h"
#include "decrypter.h"
#include "encrypter.h"

// write()
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// cryptlib
#include "cryptlib.h"


/*! \nodoc */


CRYPT_SESSION cryptSession;


int main( int argc, char *argv[] )
{
    Arena firstArena;
    Scope global( &firstArena );

    int e = 0;

    if ( argc != 5 )
        e = 1;
    else if ( String( argv[1] ) != "server" )
        e = 2;

    uint fd1, fd2, fd3;
    bool ok = true;

    if ( ok && !e )
        fd1 = String( argv[2] ).number( &ok );
    if ( ok && !e )
        fd2 = String( argv[3] ).number( &ok );
    if ( ok && !e )
        fd3 = String( argv[4] ).number( &ok );

    if ( !ok )
        e = 3;

    if ( fd1 == fd2 || fd1 == fd3 || fd2 == fd3 )
        e = 4;

    if ( e ) {
        String s( "Usage: tlsproxy server fd1 fd2 fd3\n" );
        write( 2, s.data(), s.length() );
        exit( e );
    }

    // simply assume that all three fds are okay.

    // tell the user that we've started up.
    ::write( fd3, "ok\n", 3 );
    ::close( fd3 );

    
    Configuration::setup( "mailstore.conf", "tlsproxy.conf" );

    String server = Configuration::hostname();

    /* Create the session and add the server name */
    cryptCreateSession( &cryptSession, CRYPT_UNUSED, CRYPT_SESSION_SSL_SERVER );
    cryptSetAttributeString( cryptSession, CRYPT_SESSINFO_SERVER_NAME, 
                             server.data(), server.length() );
    cryptSetAttribute( cryptSession, CRYPT_SESSINFO_NETWORKSOCKET, fd1 );
    
    Encrypter * tmp = new Encrypter( fd1, cryptSession );
    (void)new Decrypter( fd2, tmp );

    Loop::setup();

    Log l( Log::Immediate );
    global.setLog( &l );
    LogClient::setup();

    Configuration::report();
    l.commit();

    Loop::start();
}
