// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "tlsthread.h"

#include <unistd.h>

#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


static const int bs = 16384;


class TlsThreadData
    : public Garbage
{
public:
    TlsThreadData()
        : Garbage(),
          ssl( 0 ),
          ctrbo( 0 ), ctrbs( 0 ),
          ctwbo( 0 ), ctwbs( 0 ),
          ctfd( -1 ),
          encrbo( 0 ), encrbs( 0 ),
          encwbo( 0 ), encwbs( 0 ),
          encfd( -1 ),
          networkBio( 0 ), sslBio( 0 ), thread( 0 )
        {}

    SSL * ssl;
    
    char ctrb[bs];
    int ctrbo;
    int ctrbs;
    char ctwb[bs];
    int ctwbo;
    int ctwbs;
    int ctfd;
    char encrb[bs];
    int encrbo;
    int encrbs;
    char encwb[bs];
    int encwbo;
    int encwbs;
    int encfd;

    BIO * networkBio;
    BIO * sslBio;

    pthread_t * thread;
};


static void * trampoline( void * t )
{
    ((TlsThread*)t)->start();
    return 0;
}


static SSL_CTX * ctx = 0;



/*!  Constructs an empty

*/

TlsThread::TlsThread()
    : d( new TlsThreadData )
{
    if ( !ctx ) {
        // everyone does this...
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();

        ctx = ::SSL_CTX_new( SSLv23_client_method() );
        int options = SSL_OP_ALL;
        SSL_CTX_set_options( ctx, options );

        // later turn off weak ciphers here. but first find out which
        // ones are weak.

        // we don't ask for a client cert
        SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, NULL );
    }

    d->ssl = ::SSL_new( ctx );
    SSL_set_accept_state( d->ssl );

    if ( !BIO_new_bio_pair( &d->sslBio, bs, &d->networkBio, bs ) ) {
        // an error. hm?
    }
    ::SSL_set_bio( d->ssl, d->sslBio, d->sslBio );
    
    (void)pthread_create( d->thread, 0, trampoline, (void*)this );
}


/*! Destroys the object and frees any allocated resources. Except we
    probably should do this in react() or close() or something.
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
    bool again = true;
    bool crct = false;
    bool crenc = false;
    bool ctgone = false;
    bool encgone = false;
    bool finish = false;
    while ( again && !finish ) {
        again = false;

        // are our read buffers empty? if so, try to read
        if ( d->ctfd >= 0 && d->ctrbs == 0 ) {
            d->ctrbs = ::read( d->ctfd, d->ctrb, bs );
            if ( d->ctrbs > 0 )
                again = true;
            else if ( d->ctrbs == 0 && crct )
                ctgone = true;
            else if ( d->ctrbs < 0 && 
                      errno != EAGAIN && errno != EWOULDBLOCK )
                ctgone = true;
        }
        if ( d->encfd >= 0 && d->encrbs == 0 ) {
            d->encrbs = ::read( d->encfd, d->encrb, bs );
            if ( d->encrbs > 0 )
                again = true;
            else if ( d->encrbs == 0 && crenc )
                encgone = true;
            else if ( d->encrbs < 0 && 
                      errno != EAGAIN && errno != EWOULDBLOCK )
                encgone = true;
        }
        if ( ctgone && encgone ) {
            // if both file descriptors are gone, there's nothing left
            // to do. but maybe we try anyway.
            finish = true;
        }

        // is there something in our write buffers? if so, try to write
        if ( d->ctfd >= 0 && d->ctwbs > 0 ) {
            int r = ::write( d->ctfd,
                             d->ctwb + d->ctwbs,
                             d->ctwbs - d->ctwbo );
            if ( r >= 0 )
                d->ctwbo += r;
            else if ( errno != EAGAIN && errno != EWOULDBLOCK )
                finish = true;
            if ( d->ctwbo == d->ctwbs ) {
                d->ctwbs = 0;
                d->ctwbo = 0;
                again = true;
            }
        }
        if ( d->encfd >= 0 && d->encwbs > 0 ) {
            int r = ::write( d->encfd,
                             d->encwb + d->encwbs,
                             d->encwbs - d->encwbo );
            if ( r >= 0 )
                d->encwbo += r;
            else if ( errno != EAGAIN && errno != EWOULDBLOCK )
                finish = true;
            if ( d->encwbo == d->encwbs ) {
                d->encwbs = 0;
                d->encwbo = 0;
                again = true;
            }
        }

        // we've served file descriptors. now for glorious openssl.
        if ( d->encwbs == 0 ) {
            d->encwbs = BIO_read( d->networkBio, d->encwb, bs );
            if ( d->encwbs > 0 )
                again = true;
            else
                d->encwbs = 0;
        }
        if ( d->ctwbs == 0 ) {
            d->ctwbs = SSL_read( d->ssl, d->ctwb, bs );
            if ( d->ctwbs > 0 ) {
                again = true;
            }
            else {
                if ( d->ctwbs < 0 && !finish )
                    finish = sslErrorSeriousness( d->ctwbs );
                d->ctwbs = 0;
            }
        }
        if ( d->encrbs > 0 ) {
            int r = BIO_write( d->networkBio,
                               d->encrb + d->encrbo,
                               d->encrbs - d->encrbo );
            if ( r > 0 ) {
                again = true;
                d->encrbo += r;
            }
            if ( d->encrbo >= d->encrbs ) { 
                d->encrbo = 0;
                d->encrbs = 0;
            }
        }
        if ( d->ctrbs > 0 ) {
            int r = SSL_write( d->ssl,
                               d->ctrb + d->ctrbo,
                               d->ctrbs - d->ctrbo );
            if ( r > 0 ) {
                again = true;
                d->ctrbo += r;
            } else if ( r < 0 && !finish ) {
                finish = sslErrorSeriousness( r );
            }
            if ( d->ctrbo >= d->ctrbs ) { 
                d->ctrbo = 0;
                d->ctrbs = 0;
            }
        }


        if ( !finish && !again ) {
            int maxfd = -1;

            fd_set r, w;
            FD_ZERO( &r );
            FD_ZERO( &w );
            if ( d->ctfd >= 0 )
                FD_SET( d->ctfd, &r );
            if ( d->encfd >= 0 )
                FD_SET( d->encfd, &r );
            if (  d->ctfd >= 0 && d->ctwbs )
                FD_SET( d->ctfd, &w );
            if ( d->ctfd >= 0 && d->encwbs )
                FD_SET( d->encfd, &w );
            maxfd = d->ctfd;
            if ( maxfd < d->encfd )
                maxfd = d->encfd;

            struct timeval tv;
            tv.tv_sec = 3600;
            tv.tv_usec = 0;
            if ( maxfd < 0 ) {
                // if we don't have any fds yet, we wait only for 0.05s
                tv.tv_sec = 0;
                tv.tv_usec = 50000; // 0.05s
                maxfd = -1;
            }

            int n = select( maxfd+1, &r, &w, 0, &tv );
            if ( n < 0 && errno == EBADF )
                finish = true;

            crct = FD_ISSET( d->ctfd, &r );
            crenc = FD_ISSET( d->encfd, &r );
            if ( crct || crenc // if we can read something
                 || n > 0 // or something happened in select
                 || maxfd < 0 ) // or we don't have FDs yet
                again = true; // then try again
        }
    }

    ::close( d->encfd );
    ::close( d->ctfd );
    SSL_free( d->ssl );
    pthread_exit( 0 );
}

bool TlsThread::sslErrorSeriousness( int r ) {
    switch( SSL_get_error( d->ssl, r  ) ) {
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
