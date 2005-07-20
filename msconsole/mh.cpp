// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mh.h"

#include "file.h"
#include "messageset.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>


/*! \class MhDirectory mh.h

    Picks out MH mailboxes (directories containing a .mh_sequences) from
    a DirectoryTree, and hands them out one by one to the Migrator.
*/


/*! Constructs an MhDirectory for \a path. */

MhDirectory::MhDirectory( const String &path )
    : DirectoryTree( path )
{
}


bool MhDirectory::isMailbox( const String &path, struct stat *st )
{
    if ( S_ISDIR( st->st_mode ) ) {
        struct stat st;
        String s( path + "/.mh_sequences" );
        if ( stat( s.cstr(), &st ) >= 0 )
            return true;
    }

    return false;
}


MigratorMailbox * MhDirectory::newMailbox( const String &path, uint n )
{
    return new MhMailbox( path, n );
}


class MhMailboxData
    : public Garbage
{
public:
    MhMailboxData()
        : opened( false )
    {}

    bool opened;
    String path;
    MessageSet messages;
};


/*! \class MhMailbox mh.h

    This class models an MH mailbox: a directory full of numbered files,
    each containing one message. A directory is identified as a valid MH
    mailbox by the presence of an .mh_sequences file. At this time, only
    files whose names do not begin with a comma are considered, and the
    messages are not ordered.
*/


/*! Creates a new MhMailbox for \a path. The first \a n characters of
    the path are disregarded when creating target mailboxes.
*/

MhMailbox::MhMailbox( const String &path, uint n )
    : MigratorMailbox( path.mid( n ) ),
      d( new MhMailboxData )
{
    d->path = path;
}


/*! Returns a pointer to the next message in this MhMailbox, or 0 if
    there are no more messages (or if this object doesn't represent
    a valid MH mailbox).
*/

MigratorMessage * MhMailbox::nextMessage()
{
    if ( !d->opened ) {
        d->opened = true;
        DIR * dir = opendir( d->path.cstr() );
        if ( dir ) {
            struct dirent * de = readdir( dir );
            while ( de ) {
                if ( de->d_name[0] >= '1' && de->d_name[0] <= '9' ) {
                    String n( de->d_name );
                    bool ok = false;
                    uint number = n.number( &ok );
                    if ( ok )
                        d->messages.add( number );
                }
                de = readdir( dir );
            }
            closedir( dir );
        }
    }

    if ( d->messages.isEmpty() )
        return 0;

    uint i = d->messages.smallest();
    d->messages.remove( i );

    String f( d->path + "/" + String::fromNumber( i ) );
    File m( f );
    String c( m.contents() );
    if ( c.mid( 0, 5 ) == "From " ) {
        i = 0;
        while ( i < c.length() && c[i] != '\n' )
            i++;
        i++;
    }
    return new MigratorMessage( c.mid( i ), f );
}
