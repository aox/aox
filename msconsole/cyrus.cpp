// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "cyrus.h"

#include "file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>


/*! \class CyrusDirectory cyrus.h

    Picks out Cyrus mailboxes from a DirectoryTree, and hands them out
    one by one to the Migrator.
*/


/*! Constructs an CyrusDirectory for \a path. */

CyrusDirectory::CyrusDirectory( const String &path )
    : DirectoryTree( path )
{
}


bool CyrusDirectory::isMailbox( const String &path, struct stat *st )
{
    if ( S_ISDIR( st->st_mode ) ) {
        struct stat st;
        // XXX: This is bogus. But where is the Cyrus format documented?
        String s( path + "/.cyrus_metadata" );
        if ( stat( s.cstr(), &st ) >= 0 )
            return true;
    }

    return false;
}


MigratorMailbox * CyrusDirectory::newMailbox( const String &path, uint n )
{
    return new CyrusMailbox( path, n );
}


class CyrusMailboxData
    : public Garbage
{
public:
    CyrusMailboxData()
        : opened( false ), dir( 0 )
    {}

    bool opened;
    String path;
    DIR *dir;
};


/*! \class CyrusMailbox cyrus.h

    This class models a Cyrus mailbox, and is presently incomplete.
*/


/*! Creates a new CyrusMailbox for \a path. The first \a n characters
    of the path are disregarded when creating target mailboxes.
*/

CyrusMailbox::CyrusMailbox( const String &path, uint n )
    : MigratorMailbox( path.mid( n ) ),
      d( new CyrusMailboxData )
{
    d->path = path;
}


/*! Returns a pointer to the next message in this CyrusMailbox, or 0 if
    there are no more messages (or if this object doesn't represent
    a valid MH mailbox).
*/

MigratorMessage *CyrusMailbox::nextMessage()
{
    if ( !d->opened ) {
        d->opened = true;
        d->dir = opendir( d->path.cstr() );
    }

    if ( !d->dir )
        return 0;

    struct dirent *de = readdir( d->dir );
    while ( de ) {
        if ( de->d_name[0] == '.' ||
             de->d_name[0] == ',' )
        {
            // We ignore ,-prefixed names, but should we import them and
            // set \Deleted instead?
            de = readdir( d->dir );
        }
        else {
            // Do we need to check that the name is all-numerals?
            // Do we need to sort messages?
            String f( d->path + "/" + de->d_name );
            File m( f );
            return new MigratorMessage( m.contents(), f );
        }
    }

    closedir( d->dir );
    d->dir = 0;
    return 0;
}
