// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "tlsthread.h"

#include "file.h"
#include "estring.h"
#include "allocator.h"
#include "configuration.h"

#include <unistd.h>

#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


static const int bs = 32768;


class TlsThreadData
    : public Garbage
{
public:
    TlsThreadData()
        : Garbage(),
          ssl( 0 ),
          ctrb( 0 ),
          ctrbo( 0 ), ctrbs( 0 ),
          ctwb( 0 ),
          ctwbo( 0 ), ctwbs( 0 ),
          ctfd( -1 ),
          encrb( 0 ),
          encrbo( 0 ), encrbs( 0 ),
          encwb( 0 ),
          encwbo( 0 ), encwbs( 0 ),
          encfd( -1 ),
          networkBio( 0 ), sslBio( 0 ), thread( 0 ),
          broken( false ), shutdown( false )
        {}

    SSL * ssl;

    // clear-text read buffer, ie. data coming from aox
    char * ctrb;
    // the offset at which cleartext data starts
    int ctrbo;
    // and the buffer size (if ...o=...s, the buffer contains no data)
    int ctrbs;
    // clear-text write buffer, ie. data going to aox
    char * ctwb;
    int ctwbo;
    int ctwbs;
    // the cleartext fd, ie. the fd for talking to aox
    int ctfd;
    // encrypted read buffer, ie. data coming from the peer
    char * encrb;
    int encrbo;
    int encrbs;
    // encrypted write buffer, ie. data going to the peer
    char * encwb;
    int encwbo;
    int encwbs;
    int encfd;

    // where we read/write encrypted data
    BIO * networkBio;
    // where openssl reads/writes ditto
    BIO * sslBio;

    pthread_t thread;
    bool broken;
    bool shutdown;
};


static void * trampoline( void * t )
{
    ((TlsThread*)t)->start();
    return 0;
}


static SSL_CTX * ctx = 0;


/*! Perform any OpenSSL initialisation needed to enable us to create
    TlsThreads later.
*/

void TlsThread::setup()
{
    SSL_load_error_strings();
    SSL_library_init();

    ctx = ::SSL_CTX_new( SSLv23_server_method() );
    long options = SSL_OP_ALL
        // also try to pick the same ciphers suites more often
        | SSL_OP_CIPHER_SERVER_PREFERENCE
        // and don't use SSLv2, even if the client wants to
        | SSL_OP_NO_SSLv2
        // and not v3 either
        | SSL_OP_NO_SSLv3
        ;
    SSL_CTX_set_options( ctx, options );

    SSL_CTX_set_cipher_list( ctx, "kEDH:HIGH:!aNULL:!MD5" );

    EString certFile( Configuration::text( Configuration::TlsCertFile ) );
    if ( certFile.isEmpty() ) {
        certFile = Configuration::compiledIn( Configuration::LibDir );
        certFile.append( "/automatic-key.pem" );
    }
    certFile = File::chrooted( certFile );
    EString keyFile( Configuration::text( Configuration::TlsKeyFile ) );
    if ( keyFile.isEmpty() )
        keyFile = certFile;
    else
        keyFile = File::chrooted( keyFile );
    if ( !SSL_CTX_use_certificate_chain_file( ctx, certFile.cstr() ) ) {
        EString reason = ERR_reason_error_string(ERR_peek_error());
        log( "OpenSSL failed to read the certificate from " + keyFile +
             ": " + reason,
             Log::Disaster );
    }
    if ( !SSL_CTX_use_PrivateKey_file( ctx, keyFile.cstr(),
                                       SSL_FILETYPE_PEM ) )
        log( "OpenSSL needs the private key in this file: " + keyFile,
             Log::Disaster );
    // we go on anyway; the disaster will take down the server in
    // a hurry.

    // we don't ask for a client cert
    SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, NULL );
}


/*! \class TlsThread tlsthread.h
    Creates and manages a thread for TLS processing using openssl
*/



/*! Constructs a TlsThread. If \a asClient is supplied and true (the
    default is false), the thread acts as client (and initiates a TLS
    handshake). If not, it acts as a server (and expects the other end
    to initiate the handshake).
*/

TlsThread::TlsThread( bool asClient )
    : d( new TlsThreadData )
{
    if ( !ctx )
        setup();

    d->ssl = ::SSL_new( ctx );
    if ( asClient )
        SSL_set_connect_state( d->ssl );
    else
        SSL_set_accept_state( d->ssl );

    if ( !BIO_new_bio_pair( &d->sslBio, bs, &d->networkBio, bs ) ) {
        // an error. hm?
    }
    ::SSL_set_bio( d->ssl, d->sslBio, d->sslBio );

    d->ctrb = (char*)Allocator::alloc( bs, 0 );
    d->ctwb = (char*)Allocator::alloc( bs, 0 );
    d->encrb = (char*)Allocator::alloc( bs, 0 );
    d->encwb = (char*)Allocator::alloc( bs, 0 );

    int r = pthread_create( &d->thread, 0, trampoline, (void*)this );
    if ( r ) {
        log( "pthread_create returned nonzero (" + fn( r ) + ")" );
        d->broken = true;
        ::SSL_free( d->ssl );
        d->ssl = 0;
    }
}


/*! Destroys the object and frees any allocated resources. Except we
    probably should do this in Connection::react() or
    Connection::close() or something.
*/

TlsThread::~TlsThread()
{
    ::SSL_free( d->ssl );
    d->ssl = 0;
}


/*! Starts negotiating and does everything after that. This is run in
    the separate thread.

*/

void TlsThread::start()
{
    bool crct = false;
    bool crenc = false;
    bool cwct = false;
    bool cwenc = false;
    bool ctgone = false;
    bool encgone = false;
    bool finish = false;
    while ( !finish && !d->broken ) {
        // are our read buffers empty, and select said we can read? if
        // so, try to read
        if ( crct ) {
            d->ctrbs = ::read( d->ctfd, d->ctrb, bs );
            if ( d->ctrbs <= 0 ) {
                ctgone = true;
                d->ctrbs = 0;
            }
        }
        if ( crenc ) {
            d->encrbs = ::read( d->encfd, d->encrb, bs );
            if ( d->encrbs <= 0 ) {
                encgone = true;
                d->encrbs = 0;
            }
        }
        if ( ctgone && encgone ) {
            // if both file descriptors are gone, there's nothing left
            // to do. but maybe we try anyway.
            finish = true;
        }
        if ( ctgone && d->encwbs == 0 ) {
            // if the cleartext one is gone and we have nothing to
            // write to enc, finish
            finish = true;
        }
        if ( encgone && d->ctwbs == 0 ) {
            // if the encfd is gone and we have nothing to write to ct,
            // finish
            finish = true;
        }

        // is there something in our write buffers, and select() told
        // us we can write it?
        if ( cwct ) {
            int r = ::write( d->ctfd,
                             d->ctwb + d->ctwbo,
                             d->ctwbs - d->ctwbo );
            if ( r <= 0 ) {
                // select said we could, but we couldn't. parachute time.
                finish = true;
            }
            else {
                d->ctwbo += r;
                if ( d->ctwbo == d->ctwbs ) {
                    d->ctwbs = 0;
                    d->ctwbo = 0;
                }
            }
        }
        if ( cwenc ) {
            int r = ::write( d->encfd,
                             d->encwb + d->encwbo,
                             d->encwbs - d->encwbo );
            if ( r <= 0 ) {
                finish = true;
            }
            else {
                d->encwbo += r;
                if ( d->encwbo == d->encwbs ) {
                    d->encwbs = 0;
                    d->encwbo = 0;
                }
            }
        }

        // we've served file descriptors. now for glorious openssl.
        if ( d->encrbs > 0 && d->encrbo < d->encrbs ) {
            int r = BIO_write( d->networkBio,
                               d->encrb + d->encrbo,
                               d->encrbs - d->encrbo );
            if ( r > 0 )
                d->encrbo += r;
            if ( d->encrbo >= d->encrbs ) {
                d->encrbo = 0;
                d->encrbs = 0;
            }
        }
        if ( d->ctrbs > 0 && d->ctrbo < d->ctrbs ) {
            int r = SSL_write( d->ssl,
                               d->ctrb + d->ctrbo,
                               d->ctrbs - d->ctrbo );
            if ( r > 0 )
                d->ctrbo += r;
            else if ( r < 0 && !finish )
                finish = sslErrorSeriousness( r );
            if ( d->ctrbo >= d->ctrbs ) {
                d->ctrbo = 0;
                d->ctrbs = 0;
            }
        }
        if ( d->shutdown && d->ctrbo == d->ctrbs ) {
            finish = ( SSL_shutdown( d->ssl ) > 0 );
        }
        if ( d->ctwbs == 0 ) {
            d->ctwbs = SSL_read( d->ssl, d->ctwb, bs );
            if ( d->ctwbs < 0 ) {
                if ( !finish )
                    finish = sslErrorSeriousness( d->ctwbs );
                d->ctwbs = 0;
            }
        }
        if ( d->encwbs == 0 ) {
            d->encwbs = BIO_read( d->networkBio, d->encwb, bs );
            if ( d->encwbs < 0 )
                d->encwbs = 0;
        }

        if ( !finish && !d->broken ) {
            bool any = false;
            fd_set r, w;
            FD_ZERO( &r );
            FD_ZERO( &w );
            if ( d->ctfd >= 0 ) {
                if ( d->ctrbs == 0 ) {
                    FD_SET( d->ctfd, &r );
                    any = true;
                }
                if ( d->ctwbs ) {
                    any = true;
                    FD_SET( d->ctfd, &w );
                }
            }
            if ( d->encfd >= 0 ) {
                if ( d->encrbs == 0  ) {
                    any = true;
                    FD_SET( d->encfd, &r );
                }
                if ( d->encwbs ) {
                    any = true;
                    FD_SET( d->encfd, &w );
                }
            }
            int maxfd = -1;
            if ( maxfd < d->ctfd )
                maxfd = d->ctfd;
            if ( maxfd < d->encfd )
                maxfd = d->encfd;
            struct timeval tv;
            if ( maxfd < 0 ) {
                // if we don't have any fds yet, we wait for exactly 0.05s.
                tv.tv_sec = 0;
                tv.tv_usec = 50000; // 0.05s
            }
            else if ( any ) {
                // if we think there's something to do, we wait for a
                // few seconds. not very long, just in case openssl is
                // acting behind our back.
                tv.tv_sec = 2;
                tv.tv_usec = 0;
            }
            else {
                // we aren't going to read, we can't write. no point
                // in prolonging the agony.
                finish = true;
                tv.tv_sec = 0;
                tv.tv_usec = 0;
            }

            int n = finish ? 0 : select( maxfd+1, &r, &w, 0, &tv );
            if ( n < 0 && errno != EINTR )
                finish = true;

            if ( n >= 0 ) {
                crct = FD_ISSET( d->ctfd, &r );
                cwct = FD_ISSET( d->ctfd, &w );
                crenc = FD_ISSET( d->encfd, &r );
                cwenc = FD_ISSET( d->encfd, &w );
            } else {
                crct = cwct = crenc = cwenc = false;
            }

        }
    }

    if ( d->encfd >= 0 )
        ::close( d->encfd );
    if ( d->ctfd >= 0 )
        ::close( d->ctfd );
    SSL_free( d->ssl );
    d->ssl = 0;
    pthread_exit( 0 );
}


/*! Returns true if the openssl result status \a r is a serious error,
    and false otherwise.
*/

bool TlsThread::sslErrorSeriousness( int r ) {
    int e = SSL_get_error( d->ssl, r  );
    switch( e ) {
    case SSL_ERROR_NONE:
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_X509_LOOKUP:
        return false;
        break;

    case SSL_ERROR_ZERO_RETURN:
        // not an error, client closed cleanly
        return true;
        break;

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
        //ERR_print_errors_fp( stdout );
        return true;
        break;
    }
    return true;
}


/*! Records that \a fd should be used for cleartext communication with
    the main aox thread. The TLS thread will close \a fd when it's done.
*/

void TlsThread::setServerFD( int fd )
{
    d->ctfd = fd;
}


/*! Records that \a fd should be used for encrypted communication with
    the client. The TLS thread will close \a fd when it's done.
*/

void TlsThread::setClientFD( int fd )
{
    d->encfd = fd;
}


/*! Returns true if this TlsThread is broken somehow, and false if
    it's in working order.
*/

bool TlsThread::broken() const
{
    return d->broken;
}


/*! Initiates a very orderly shutdown.
*/

void TlsThread::shutdown()
{
    d->shutdown = true;
}


/*! Returns true if this TlsThread has been told to shut down via
    shutdown(), and false if not.
*/

bool TlsThread::isShuttingDown() const
{
    return d->shutdown;
}


/*! Causes this TlsThread object to stop doing anything, in a great
    hurry and without any attempt at talking to the client.
*/

void TlsThread::close()
{
    int encfd = d->encfd;
    int ctfd = d->ctfd;
    d->broken = true;
    d->encfd = -1;
    d->ctfd = -1;
    if ( encfd >= 0 )
        ::close( encfd );
    if ( ctfd >= 0 )
        ::close( ctfd );
    pthread_cancel( d->thread );
    pthread_join( d->thread, 0 );
}
