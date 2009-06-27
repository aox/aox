// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "file.h"

#include "estring.h"
#include "allocator.h"
#include "scope.h"
#include "log.h"

// fstat
#include <sys/types.h>
#include <sys/stat.h>
// read
#include <sys/uio.h>
#include <unistd.h>
// open
#include <fcntl.h>

// we want large file support if available, but don't care
#if !defined(O_LARGEFILE)
#define O_LARGEFILE 0
#endif


extern "C" void *memcpy(void *, const void *, uint);


class FileData
    : public Garbage
{
public:
    FileData()
        : fd( -1 ), t( 0 ), ok( false )
    {}

    int fd;
    EString n;
    EString c;
    uint t;
    bool ok;
};


/*! \class File file.h
    Represents a file.

    A file is read once on object construction and never read later, or
    opened and truncated, ready for later writing.

    Once read, a file's contents() returns the entire contents of the
    file. To write to a file, write() is available. The file remains
    open until the destructor is called.

    modificationTime() returns an integer that's bigger for more
    recently modified/created files, name() returns the file's name
    and valid() returns true or false depending on whether everything
    is okay.
*/


/*! Creates a new unnamed File representing the specified \a fd. This is
    used only by the LogServer to write to stdout.
*/

File::File( int fd )
    : d( new FileData )
{
    d->fd = fd;
    if ( d->fd >= 0 )
        d->ok = true;
}


/*! Creates a new File object representing \a name, and tries to open it
    and read up to \a maxLength bytes, or the whole file if \a maxLength
    is 0.
*/

File::File( const EString &name, uint maxLength )
    : d( new FileData )
{
    init( name, File::Read, 0, maxLength );
}


/*! Creates a new File object representing \a name. If \a a is Read, the
    contents of the file are read. If \a a is Write, the file is opened
    for writing and truncated. If \a a is Append, the file is opened for
    append. In the latter cases, the file is created with the specified
    \a mode if it does not exist.
*/

File::File( const EString &name, File::Access a, uint mode )
    : d( new FileData )
{
    init( name, a, mode, 0 );
}


/*! Initialises a file object to represent \a name, which is opened for
    the specified \a mode. If \a a is Read, \a maxLength specifies the
    number of bytes to read; and if \a a is Write or Append, the \a mode
    is used if the file is to be created.
*/

void File::init( const EString &name, File::Access a,
                 uint mode, uint maxLength )
{
    d->n = name;

    EString chn = chrooted( name );

    switch ( a ) {
    case Read:
        d->fd = ::open( chn.cstr(),
                        O_RDONLY );
        break;
    case Write:
        d->fd = ::open( chn.cstr(),
                        O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, mode );
        break;
    case Append:
        d->fd = ::open( chn.cstr(),
                        O_APPEND|O_WRONLY|O_CREAT|O_LARGEFILE, mode );
        break;
    case ExclusiveWrite:
        d->fd = ::open( chn.cstr(),
                        O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE, mode );
        break;
    }

    if ( d->fd < 0 )
        return;

    struct stat st;
    if ( fstat( d->fd, &st ) < 0 )
        return;
    d->t = st.st_ctime;
    if ( d->t < (uint)st.st_mtime )
        d->t = st.st_mtime;

    if ( a != Read ) {
        d->ok = true;
        return;
    }

    int n = maxLength;
    if ( maxLength == 0 || maxLength > 1024 * 1024 ) {
        // if (int)maxLength() <= 0, this ensures that n ends up
        // positive.
        n = st.st_size;
        if ( n == 0 )
            n = 16*1024;
    }

    int l;
    int total = 0;
    int size = n+1;
    char *b = (char *)Allocator::alloc( size, 0 );
    b[0] = '\0';
    b[n] = '\0';

    do {
        l = ::read( d->fd, b+total, n - total );
        if ( l > 0 ) {
            total += l;
            if ( total >= n )
                l = -1;
        }
    }
    while ( l > 0 );

    d->c = EString( b, total );

    ::close( d->fd );
    d->fd = -1;
    d->ok = true;
}


/*! Returns the name of the file, as specified to the constructor. */

EString File::name() const
{
    return d->n;
}


/*! Returns the contents of the file as read by the constructor. If
    this file is being written to, not read, then contents() returns
    an empty string. */

EString File::contents() const
{
    return d->c;
}


/*! Returns a non-zero pointer to a EStringList containing the lines of
    text read from this File. The lines are returned unmodified, with
    trailing CRLF, if any, intact.
*/

EStringList * File::lines()
{
    EStringList * lines = new EStringList;

    int i = 0;
    int last = 0;
    while ( ( i = d->c.find( '\n', last ) ) != -1 ) {
        lines->append( d->c.mid( last, i-last+1 ) );
        last = i+1;
    }
    if ( last >= 0 && last < (int)d->c.length() )
        lines->append( d->c.mid( last ) );

    return lines;
}


/*! Destroyes the file and closes it if it still is open. */

File::~File()
{
    if ( d->fd >= 0 )
        ::close( d->fd );
}


/*! Returns the modification time of this file as it was at time of
    construction. The modification time is an opaque integer; its
    meaning is not specified except that more recently
    created/modified files have larger values of modificationTime().
*/

uint File::modificationTime() const
{
    return d->t;
}


/*! Returns true if this file was opened and read correctly, and false
    if the object is somehow invalid.
*/

bool File::valid() const
{
    return d->ok;
}


/*! Writes \a s to the end of the file if this file is open for
    writing, and does nothing else.

    OS errors are disregarded.
*/

void File::write( const EString & s )
{
    if ( d->fd >= 0 && s.length() > 0 )
        ::write( d->fd, s.data(), s.length() );
}


static EString * root = 0;

/*! Records that the root directory is now \a d. The initial value is
    "/". This value is used by chrooted().

    If \a d does not end with a '/', setRoot() appends one.
*/

void File::setRoot( const EString & d )
{
    if ( d == root() )
        return;
    *::root = d;
    if ( !::root->endsWith( "/" ) )
        *::root += "/";
}


/*! Returns the currently recorded root directory, which always starts
    and ends with a '/' character. This is just the argument of the
    last setRoot() call.
*/

EString File::root()
{
    if ( !::root ) {
        ::root = new EString;
        Allocator::addEternal( ::root, "root directory name" );
    }
    if ( ::root->isEmpty() )
        *::root = "/";
    return *::root;
}


/*! Returns the current name of \a filename based on the root() in
    effect, if \a filename starts with a '/'.

    If \a filename is a relative name, this function does nothing.

    The current root() is assumed to match the chroot directory used
    by the operating system.  If \a filename isn't within root(),
    chrooted() logs an error.  Thus, when a server runs inside chroot
    jail, attempts to open files or unix sockets cause sensible error
    messages.
*/

EString File::chrooted( const EString & filename )
{
    if ( filename[0] != '/' )
        return filename; // it's relative. can't check that case.
    if ( filename.startsWith( root() ) )
        return filename.mid( root().length() - 1 );
    log( filename + " is not within root directory " + root(),
         Log::Error );
    return filename;
}


/*! Removes the file with name \a s. All operating system errors are
    blithely ignored.
*/

void  File::unlink( EString s )
{
    ::unlink( s.cstr() );
}
