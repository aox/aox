// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "buffer.h"

#include "sys.h"
#include "list.h"
#include "string.h"
#include "allocator.h"

// errno
#include <errno.h>
// open, O_CREAT|O_RDWR|O_EXCL
#include <fcntl.h>
// struct iovec
#include <sys/uio.h>
// read, write, unlink, lseek, close
#include <unistd.h>


class BufferData {
public:
    BufferData()
        : eof( false ), firstused( 0 ), firstfree( 0 ), size( 0 )
    {}

    int fd;
    bool eof;
    List< struct iovec > vecs;
    uint firstused, firstfree;
    uint size;
};


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

/*! Creates an empty Buffer.
*/

Buffer::Buffer()
    : d( new BufferData )
{
}


/*! Destroys a Buffer, freeing all allocated memory, and discarding all
    buffered data.
*/

Buffer::~Buffer()
{
    delete d;
    d = 0;
}


/*! Appends \a l bytes starting at \a s to the Buffer. If \a l is 0 (the
    default), \a s is considered to be NUL-terminated.
*/

void Buffer::append( const char *s, uint l )
{
    if ( l == 0 )
        l = strlen( s );
    if ( l == 0 )
        return;

    d->size += l;

    // First, we copy as much as we can into the last vector.
    uint n, copied = 0;
    struct iovec *v = d->vecs.last();
    if ( v && (n = v->iov_len - d->firstfree) > 0 ) {
        if ( n > l )
            n = l;

        memmove((char *)v->iov_base+d->firstfree, s, n);
        d->firstfree += n;
        copied = n;

    }

    // Then we use a new vector for the rest.
    if ( copied < l ) {
        int remains = l - copied;
        struct iovec *f = f = new struct iovec;
        f->iov_len = remains;
        if ( f->iov_len < 1024 )
            f->iov_len = 1024;
        f->iov_len = Allocator::rounded( f->iov_len );
        f->iov_base = (char*)::alloc( f->iov_len );

        if ( d->vecs.isEmpty() )
            d->firstused = 0;
        d->vecs.append(f);

        int n = f->iov_len;
        if ( n > remains )
            n = remains;

        memmove(f->iov_base, s+copied, n);
        d->firstfree = n;
        copied += n;
    }
}


/*! \overload
    Appends the String \a s to a Buffer.
*/

void Buffer::append(const String &s)
{
    if ( s.length() > 0 )
        append( (char *)s.data(), s.length() );
}


/*! Reads as much as possible from the file descriptor \a fd into the
    Buffer. It assumes that the file descriptor is nonblocking, and
    that enough memory is available.
*/

void Buffer::read( int fd )
{
    char buf[8192];

    int n = 0;
    do {
        n = ::read( fd, &buf, 8192 );

        if ( n > 0 ) {
            d->eof = false;
            append( buf, n );
        }
        else if ( n == 0 ) {
            d->eof = true;
        }
        else if ( errno != EAGAIN &&
                  errno != EWOULDBLOCK )
        {
            die( FD );
        }
    } while ( n > 0 );
}


/*! Writes as much as possible from the Buffer to its file descriptor
    \a fd. That file descriptor must be nonblocking.
*/

void Buffer::write( int fd )
{
    int written = 0;

    do {
        struct iovec *v = d->vecs.first();

        if ( !v )
            return;

        int max = v->iov_len;
        if ( d->vecs.count() == 1 )
            max = d->firstfree;
        int n = max - d->firstused;

        written = ::write( fd, (char *)v->iov_base+d->firstused, n );
        if ( written > 0 )
            remove(written);
        else if ( written < 0 && errno != EAGAIN )
            die( FD );
    }
    while ( written > 0 );
}


/*! Have we encountered EOF when reading into this buffer? */

bool Buffer::eof() const
{
    return d->eof;
}


/*! Returns the number of bytes in the Buffer. */

uint Buffer::size() const
{
    return d->size;
}


/*! Discards the first \a n bytes from the Buffer. If there are fewer
    than \a n bytes in the Buffer, the Buffer is left empty.
*/

void Buffer::remove( uint n )
{
    if ( n > d->size )
        n = d->size;
    d->size -= n;

    struct iovec *v = d->vecs.first();

    while ( v && n >= v->iov_len - d->firstused ) {
        n -= v->iov_len - d->firstused;
        d->firstused = 0;
        d->vecs.shift();
        v = d->vecs.first();
    }
    if ( v ) {
        d->firstused += n;
        if ( d->firstused >= d->firstfree && d->vecs.count() == 1 ) {
            d->vecs.shift();
            d->firstused = d->firstfree = 0;
        }
    }
    else {
        d->firstused = 0;
    }
}


/*! \fn char Buffer::operator[]( uint i ) const

    Returns the byte at index \a i of the Buffer. Returns 0 if \a i is
    too large, or the buffer is empty.
*/


/*! \overload
*/

char Buffer::at( uint i ) const
{
    uint n = i + d->firstused;

    // Optimise heavily for the common case.
    struct iovec *v = d->vecs.firstElement();
    if ( v && v->iov_len > n )
        return *( (char *)v->iov_base + n );

    if ( i >= d->size )
        return 0;

    List< struct iovec >::Iterator it( d->vecs );

    v = it;
    while ( n >= v->iov_len ) {
        n -= v->iov_len;
        ++it;
        v = it;
    }

    return *( (char *)v->iov_base + n );
}


/*! Returns a string containing the first \a num bytes in the buffer. If
    the buffer contains fewer than \a num bytes, they are all returned.
    This function does not remove() the returned data.
*/

String Buffer::string( uint num ) const
{
    String result;
    uint n = size();

    if ( n == 0 )
        return result;
    if ( num < n )
        n = num;
    result.reserve( n );

    List< struct iovec >::Iterator it( d->vecs );
    struct iovec *v = it;

    int max = v->iov_len;

    if ( d->vecs.count() == 1 )
        max = d->firstfree;

    uint copied = max - d->firstused;

    if ( copied > n )
        copied = n;

    result.append( (const char *)v->iov_base + d->firstused, copied );

    while ( copied < n ) {
        v = ++it;
        uint l = v->iov_len;
        if ( copied + l > n )
            l = n - copied;
        result.append( (const char *)v->iov_base, l );
        copied += l;
    }

    return result;
}


/*! This function removes a line (terminated by LF or CRLF) of at most
    \a s bytes from the Buffer, and returns a pointer to a String with
    the line ending removed. If the Buffer does not contain a complete
    line less than \a s bytes long, this function a null pointer.

    If \a s has its default value of 0, the entire Buffer is searched.
*/

String * Buffer::removeLine( uint s )
{
    uint i = 0, n = 0;
    String * r;

    if ( s == 0 )
        s = size();

    while ( i < s ) {
        if ( (*this)[i] == '\015' && (*this)[i+1] == '\012' )
            n = 2;
        else if ( (*this)[i] == '\012' )
            n = 1;
        if ( n > 0 )
            break;
        i++;
    }

    if ( !n )
        return 0;

    r = new String( string( i ) );
    remove( i+n );
    return r;
}


