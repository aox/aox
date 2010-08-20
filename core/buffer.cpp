// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "buffer.h"

#include "list.h"
#include "estring.h"
#include "allocator.h"

// open, O_CREAT|O_RDWR|O_EXCL
#include <fcntl.h>
// read, write, unlink, lseek, close
#include <unistd.h>
// strlen, memmove
#include <string.h>

#include <zlib.h>


static const uint bufsiz = 8192;
static char buffer[bufsiz];



/*! \class Buffer buffer.h
    A Buffer is a FIFO of bytes.

    There are two ways to append data: append() and read(). Data in
    the buffer can be examined with operator[] or string(), removed
    with remove(), or written with write().

    Generally, a buffer is used only to read or only to write. In the
    former case, its owner calls append() and EventLoop calls write(),
    and in the latter EventLoop calls read() and the object's owner
    calls remove() etc. However, its owner has the option of putting
    things into the buffer and later removing them. One class does use
    that: IMAPS.
*/

/*! Creates an empty Buffer. */

Buffer::Buffer()
    : filter( None ), zs( 0 ),
      firstused( 0 ), firstfree( 0 ),
      bytes( 0 )
{
}


/*! Appends \a l bytes starting at \a s to the Buffer.
*/

void Buffer::append( const char * s, uint l )
{
    if ( l )
        append( s, l, true );
}


/*! This private helper is the only way to actually write data into
    the Buffer. read() and append() always call this.

    \a s points to the start of the bytes to be appended and should
    not be null. \a l is the length, which may be 0. If \a f is true,
    then all of \a s is pushed through zlib, while if \a f is false,
    zlib is given the option of looking at later input to compress
    better.
*/

void Buffer::append( const char * s, uint l, bool f )
{
    int r = Z_OK;
    bool progress = true;

    switch ( filter ) {
    case Compressing:
        zs->avail_in = l;
        zs->next_in = (Bytef*)s;
        while ( zs->avail_in && progress && r == Z_OK ) {
            zs->next_out = (Bytef*)buffer;
            zs->avail_out = bufsiz;
            r = ::deflate( zs, Z_NO_FLUSH );
            if ( zs->avail_out < bufsiz )
                append2( buffer, bufsiz - zs->avail_out );
            else
                progress = false;
        }
        if ( f ) {
            zs->next_out = (Bytef*)buffer;
            zs->avail_out = bufsiz;
            r = ::deflate( zs, Z_SYNC_FLUSH );
            if ( zs->avail_out < bufsiz )
                append2( buffer, bufsiz - zs->avail_out );
        }
        if ( zs->avail_in ) {
            // should not happen
        }
        break;

    case Decompressing:
        zs->avail_in = l;
        zs->next_in = (Bytef*)s;
        while ( zs->avail_in && progress && r == Z_OK ) {
            zs->next_out = (Bytef*)buffer;
            zs->avail_out = bufsiz;
            r = ::inflate( zs, Z_SYNC_FLUSH );
            if ( zs->avail_out < bufsiz )
                append2( buffer, bufsiz - zs->avail_out );
            else
                progress = false;
        }
        break;

    case None:
        append2( s, l );
        break;
    }
}


/*! This internal helper for append writes already-compressed or
    already-decompressed data to the internal buffer. \a s and \a l
    are as for append(), but de-/compressed.

    \a s must not be null, \a l must not be zero.
*/

void Buffer::append2( const char * s, uint l )
{
    bytes += l;

    // First, we copy as much as we can into the last vector.
    uint n, copied = 0;
    Vector *v = vecs.last();
    if ( v && (n = v->len - firstfree) > 0 ) {
        if ( n > l )
            n = l;

        memmove(v->base+firstfree, s, n);
        firstfree += n;
        copied = n;

    }

    // Then we use a new vector for the rest.
    if ( copied < l ) {
        int remains = l - copied;
        Vector *f = new Vector;
        f->len = remains;
        if ( f->len < 1500 )
            f->len = 1500;
        f->len = Allocator::rounded( f->len );
        f->base = (char*)Allocator::alloc( f->len, 0 );

        if ( vecs.isEmpty() )
            firstused = 0;
        vecs.append(f);

        int n = f->len;
        if ( n > remains )
            n = remains;

        memmove(f->base, s+copied, n);
        firstfree = n;
        copied += n;
    }
}


/*! \overload
    Appends the EString \a s to a Buffer.
*/

void Buffer::append( const EString &s )
{
    if ( s.length() > 0 )
        append( s.data(), s.length() );
}


/*! Reads as much as possible from the file descriptor \a fd into the
    Buffer. It assumes that the file descriptor is nonblocking, and
    that enough memory is available.
*/

void Buffer::read( int fd )
{
    char buf[32768];

    int n = ::read( fd, &buf, 32768 );
    while ( n > 0 ) {
        append( buf, n );
        n = ::read( fd, &buf, 32768 );
    }
}


/*! Writes as much as possible from the Buffer to its file descriptor
    \a fd. That file descriptor must be nonblocking.
*/

void Buffer::write( int fd )
{
    int written = 1;

    while ( written > 0 ) {
        Vector * v = vecs.firstElement();

        int max = 0;
        if ( v )
            max = v->len;
        if ( vecs.count() == 1 )
            max = firstfree;
        int n = max - firstused;

        if ( n <= 0 || !v )
            written = 0;
        else
            written = ::write( fd, v->base+firstused, n );
        if ( written > 0 )
            remove( written );
    }
}


/*! \fn uint Buffer::size() const
    Returns the number of bytes in the Buffer.
*/


/*! Discards the first \a n bytes from the Buffer. If there are fewer
    than \a n bytes in the Buffer, the Buffer is left empty.
*/

void Buffer::remove( uint n )
{
    if ( n > bytes )
        n = bytes;
    bytes -= n;

    Vector *v = vecs.firstElement();

    if ( bytes == 0 ) {
        firstused = firstfree = 0;
        vecs.clear();
        if ( v && ( v->len > 100 && v->len < 20000 ) )
            vecs.append( v );
        return;
    }

    while ( v && n >= v->len - firstused ) {
        n -= v->len - firstused;
        firstused = 0;
        vecs.shift();
        v = vecs.firstElement();
    }
    if ( v ) {
        firstused += n;
        if ( firstused >= firstfree && vecs.count() == 1 ) {
            vecs.shift();
            firstused = firstfree = 0;
        }
    }
    else {
        firstused = 0;
    }
}


/*! \fn char Buffer::operator[]( uint i ) const

    Returns the byte at index \a i of the Buffer. Returns 0 if \a i is
    too large, or the buffer is empty.
*/


/*! This private function retrieves bytes that are not in the first
    Vector on behalf of operator[](). It's kept here to make the inline
    function smaller. \a i is an internal variable, and this function
    should never be called except from the operator.
*/

char Buffer::at( uint i ) const
{
    List< Vector >::Iterator it( vecs );

    Vector *v = it;
    while ( i >= v->len ) {
        i -= v->len;
        ++it;
        v = it;
    }

    return *( v->base + i );
}


/*! Returns a string containing the first \a num bytes in the buffer. If
    the buffer contains fewer than \a num bytes, they are all returned.
    This function does not remove() the returned data.
*/

EString Buffer::string( uint num ) const
{
    EString result;
    uint n = size();

    if ( n == 0 )
        return result;
    if ( num < n )
        n = num;
    result.reserve( n );

    List< Vector >::Iterator it( vecs );
    Vector *v = it;

    int max = v->len;

    if ( vecs.count() == 1 )
        max = firstfree;

    uint copied = max - firstused;

    if ( copied > n )
        copied = n;

    result.append( v->base + firstused, copied );

    while ( copied < n ) {
        v = ++it;
        uint l = v->len;
        if ( copied + l > n )
            l = n - copied;
        result.append( v->base, l );
        copied += l;
    }

    return result;
}


/*! This function removes a line (terminated by LF or CRLF) of at most
    \a s bytes from the Buffer, and returns a pointer to a EString with
    the line ending removed. If the Buffer does not contain a complete
    line less than \a s bytes long, this function a null pointer.

    If \a s has its default value of 0, the entire Buffer is searched.
*/

EString * Buffer::removeLine( uint s )
{
    uint i = 0, n = 0;
    EString * r;

    if ( s == 0 || s > size() )
        s = size();

    while ( i < s && (*this)[i] != '\012' )
        i++;

    if ( i == s )
        return 0;

    n = 1;
    if ( i > 0 && (*this)[i-1] == '\015' ) {
        i--;
        n++;
    }

    r = new EString( string( i ) );
    remove( i+n );
    return r;
}


static void * allocwrapper( void *, uint i, uint s ) {
    return Allocator::alloc( i*s );
}

static void deallocwrapper( void *, void * x ) {
    Allocator::dealloc( x );
}


/*! Instructs this Buffer to compress any data added if \a c is
    Compressing, and to decompress if \a c is Decompressing.
  
    \a c should never be None; that's the initial state, and it's
    impossible to get back to the initial state.
*/

void Buffer::setCompression( Compression c )
{
    zs = (z_stream *)Allocator::alloc( sizeof( z_stream ) );
    zs->zalloc = &allocwrapper;
    zs->zfree = &deallocwrapper;
    zs->opaque = 0;
    if ( c == Compressing )
        ::deflateInit2( zs, 9, Z_DEFLATED,
                        -15, 9, Z_DEFAULT_STRATEGY );
    else if ( c == Decompressing )
        ::inflateInit2( zs, -15 );
    filter = c;
}


/*! Returns Compressing, Decompressing or None depending on what's
    done to data added to the Buff. The initial value is None.
*/

Buffer::Compression Buffer::compression() const
{
    return filter;
}
