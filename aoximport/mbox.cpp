// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mbox.h"

#include "stringlist.h"
#include "file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>


/*! \class MboxDirectory mbox.h

    The MboxDirectory class models a hierarchy of directories and mbox
    files. It hands out the name of one mbox file at a time via the
    MigratorSource API.
*/


/*!  Constructs an MboxDirectory for \a path. */

MboxDirectory::MboxDirectory( const String & path )
    : DirectoryTree( path )
{
}


bool MboxDirectory::isMailbox( const String &, struct stat *st )
{
    if ( S_ISREG( st->st_mode ) )
        return true;
    return false;
}


MigratorMailbox * MboxDirectory::newMailbox( const String &path, uint n )
{
    return new MboxMailbox( path, n );
}


class MboxMailboxData
    : public Garbage
{
public:
    MboxMailboxData(): file( 0 ), msn( 1 ) {}

    String path;
    FILE * file;
    uint msn;
};


/*! \class MboxMailbox mbox.h

    The MboxMailbox class models a single mbox file, providing
    MigratorMessage objects to Migrator using the MigratorMailbox
    API. Very simple.

    Files which aren't mbox files are viewed as zero-message mailboxes.
*/

/*!  Constructs an MboxMailbox for \a path. If \a path isn't a valid
     file, or if it doesn't seem to be an mbox file, the result is an
     MboxMailbox containing zero messages. The first \a n character of
     \a path are disregarded when creating the target mailboxes.
*/

MboxMailbox::MboxMailbox( const String & path, uint n )
    : MigratorMailbox( path.mid( n ) ), d( new MboxMailboxData )
{
    d->path = path;
}


static bool isFrom( const char * s )
{
    String f( s );

    if ( !f.startsWith( "From " ) )
        return false;

    uint n = 5;
    while ( n < f.length() &&
            !( s[n] == ' ' &&
               ( s[n+1] >= '0' && s[n+1] <= '9' ) &&
               ( s[n+2] >= '0' && s[n+2] <= '9' ) &&
               s[n+3] == ':' &&
               ( s[n+4] >= '0' && s[n+4] <= '9' ) &&
               ( s[n+5] >= '0' && s[n+5] <= '9' ) &&
               s[n+6] == ':' &&
               ( s[n+7] >= '0' && s[n+7] <= '9' ) &&
               ( s[n+8] >= '0' && s[n+8] <= '9' ) &&
               s[n+9] == ' ' &&
               ( s[n+10] >= '0' && s[n+10] <= '9' ) &&
               ( s[n+11] >= '0' && s[n+11] <= '9' ) &&
               ( s[n+12] >= '0' && s[n+12] <= '9' ) &&
               ( s[n+13] >= '0' && s[n+13] <= '9' ) ) )
    {
        n++;
    }

    // Did we find "11:22:33 4567" in the line?
    if ( f[n] == '\0' )
        return false;

    return true;
}


/*! This reimplementation does a rough parsing of mbox files. It's
    difficult to know how to parse those things - how flexible should
    we be? Should we insist on a correct date, for example?

    For the moment, we use this, and as we find a need to tweak it, we
    build a regression test suite.
*/

MigratorMessage * MboxMailbox::nextMessage()
{
    char s[128];

    if ( !d->file ) {
        d->file = fopen( d->path.cstr(), "r" );
        // If we can't read a "From " line at the very beginning, we
        // assume this isn't an mbox, and give up.
        if ( !d->file || fgets( s, 128, d->file ) == 0 ||
             !( s[0] == 'F' && s[1] == 'r' && s[2] == 'o' && s[3] == 'm' &&
                s[4] == ' ' ) )
            return 0;
    }

    String contents;
    bool done = false;
    while ( !done ) {
        if ( fgets( s, 128, d->file ) != 0 && !isFrom( s ) )
            contents.append( s );
        else
            done = true;
    }

    if ( contents.isEmpty() )
        return 0;

    MigratorMessage * m
        = new MigratorMessage( contents, d->path + ":" + fn( d->msn ) );

    d->msn++;
    List<HeaderField>::Iterator it( m->message()->header()->fields() );
    while( it && it->name() != "Status" )
        ++it;
    if ( it ) {
        String v = it->value().simplified();
        uint f = 0;
        while ( f < v.length() ) {
            switch( v[f] ) {
            case 'R':
            case 'O':
                m->addFlag( "\\seen" );
                break;
            case 'D':
                m->addFlag( "\\deleted" );
                break;
            case 'U':
            case 'S':
                // should clear \\seen, but that's already the case
                break;
            }
            ++f;
        }
        
    }

    return m;
}
