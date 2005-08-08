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
// read, write, unlink, lseek, close
#include <unistd.h>


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
    : firstused( 0 ), firstfree( 0 ), seenEOF( false ), bytes( 0 )
{
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
        if ( f->len < 16384 )
            f->len = 16384;
        f->len = Allocator::rounded( f->len );
        f->base = (char*)Allocator::alloc( f->len );

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
    Appends the String \a s to a Buffer.
*/

void Buffer::append(const String &s)
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
    char buf[8192];

    int n = 0;
    do {
        n = ::read( fd, &buf, 8192 );

        if ( n > 0 ) {
            seenEOF = false;
            append( buf, n );
        }
        else if ( n == 0 ||
                  errno == ECONNRESET )
        {
            seenEOF = true;
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
        Vector *v = vecs.firstElement();

        if ( !v )
            return;

        int max = v->len;
        if ( vecs.count() == 1 )
            max = firstfree;
        int n = max - firstused;

        written = 0;
        if ( n )
            written = ::write( fd, v->base+firstused, n );
        if ( written > 0 )
            remove( written );
        else if ( written < 0 && errno != EAGAIN )
            die( FD );
    }
    while ( written > 0 );
}


/*! Have we encountered EOF when reading into this buffer? */

bool Buffer::eof() const
{
    return seenEOF;
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

String Buffer::string( uint num ) const
{
    String result;
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
    \a s bytes from the Buffer, and returns a pointer to a String with
    the line ending removed. If the Buffer does not contain a complete
    line less than \a s bytes long, this function a null pointer.

    If \a s has its default value of 0, the entire Buffer is searched.
*/

String * Buffer::removeLine( uint s )
{
    uint i = 0, n = 0;
    String * r;

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

    r = new String( string( i ) );
    remove( i+n );
    return r;
}


