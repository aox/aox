// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mbox.h"

#include "stringlist.h"
#include "file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>


class MboxMailboxData
{
public:
    MboxMailboxData(): read( false ), offset( 0 ) {}

    String path;
    bool read;
    uint offset;
    String contents;
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


/*! This reimplementation does a rough parsing of mbox files. It's
    difficult to know how to parse those things - how flexible should
    we be? Should we insist on a correct date, for example?

    For the moment, we use this, and as we find a need to tweak it, we
    build a regression test suite.
*/

MigratorMessage * MboxMailbox::nextMessage()
{
    if ( !d->read ) {
        File r( d->path );
        d->offset = 0;
        d->contents = r.contents();
        d->read = true;
    }

    if ( d->contents.mid( d->offset, 5 ) != "From " )
        return 0;

    uint i = d->offset + 1;
    while ( i < d->contents.length() &&
            !( d->contents[i-1] == '\n' &&
               d->contents[i] == 'F' &&
               d->contents.mid( i, 5 ) != "From " ) )
        i++;

    MigratorMessage * m
        = new MigratorMessage( d->contents.mid( d->offset,
                                                i - d->offset ),
                               d->path + ":" + fn( d->offset ) );
    d->offset = i;

    return m;
}


class MboxDirectoryData {
public:
    MboxDirectoryData(): prefixLength( 0 ) {}
    StringList paths;
    uint prefixLength;
};


/*! \class MboxDirectory mbox.h

    The MboxDirectory class models a hierchy of directories and mbox
    files. It hands out the name of one mbox file at a time via the
    MigratorSource API.
*/


/*!  Constructs an MboxDirectory for \a path. */

MboxDirectory::MboxDirectory( const String & path )
    :d( new MboxDirectoryData )
{
    if ( path.length() > 0 && path[path.length()-1] == '/' )
        d->paths.append( path.mid( 0, path.length()-1 ) );
    else
        d->paths.append( path );
    d->prefixLength = d->paths.first()->length();
}


MboxMailbox * MboxDirectory::nextMailbox()
{
    String * p = 0;
    while ( !p ) {
        if ( d->paths.isEmpty() )
            return 0;

        p = d->paths.shift();
        struct stat st;
        if ( stat( p->cstr(), &st ) < 0 )
            // deleted since we looked at it
            p = 0;
        else if ( S_ISREG( st.st_mode ) ) {
            // done
        }
        else if ( S_ISDIR( st.st_mode ) ) {
            DIR * dp = opendir( p->cstr() );
            if ( dp ) {
                struct dirent * de = readdir( dp );
                while ( de ) {
                    if ( ( de->d_namlen == 1 && de->d_name[0] == '.' ) ||
                         ( de->d_namlen == 2 &&
                           de->d_name[0] == '.' &&
                           de->d_name[1] == '.' ) ) {
                        // we don't want those two
                    }
                    else {
                        String * tmp = new String;
                        tmp->reserve( p->length() + 1 + de->d_namlen );
                        tmp->append( *p );
                        tmp->append( "/" );
                        tmp->append( de->d_name, de->d_namlen );
                        d->paths.append( tmp );
                    }
                    de = readdir( dp );
                }
                closedir( dp );
            }
            p = 0;
        }
        else {
            // a symlink? a device node? whatever it is, we ignore it
            p = 0;
        }
    }
    if ( !p )
        return 0;
    return new MboxMailbox( *p, d->prefixLength );
}
