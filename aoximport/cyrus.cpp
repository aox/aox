// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cyrus.h"

#include "file.h"
#include "messageset.h"

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
        String s( path + "/cyrus.seen" );
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
        : opened( false )
    {}

    bool opened;
    String path;
    MessageSet messages;
    MessageSet seen;
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
        DIR * dir = opendir( d->path.cstr() );
        if ( dir ) {
            struct dirent * de = readdir( dir );
            while ( de ) {
                if ( de->d_name[0] >= '1' && de->d_name[0] <= '9' ) {
                    uint i = 0;
                    while ( de->d_name[i] >= '0' && de->d_name[i] <= '9' )
                        i++;
                    if ( de->d_name[i] == '.' ) {
                        String n( de->d_name, i );
                        bool ok = false;
                        uint number = n.number( &ok );
                        if ( ok )
                            d->messages.add( number );
                    }
                }
                de = readdir( dir );
            }
            closedir( dir );
        }
        File seen( d->path + "/cyrus.seen", File::Read );
        StringList::Iterator l( seen.lines() );
        bool ok = true;
        while ( l && ok ) {
            String line = l->simplified();
            ++l;
            while ( line.contains( ' ' ) )
                line = line.mid( line.find( ' ' ) + 1 );
            uint e = 0;
            while ( ok && e < line.length() ) {
                uint b = e;
                while ( line[e] >= '0' && line[e] <= '9' )
                    e++;
                uint first = line.mid( b, e-b ).number( &ok );
                uint second = first;
                if ( line[e] == ':' ) {
                    e++;
                    b = e;
                    while ( line[e] >= '0' && line[e] <= '9' )
                        e++;
                    second = line.mid( b, e-b ).number( &ok );
                }
                if ( line[e] == ',' || e >= line.length() )
                    d->seen.add( first, second );
                else
                    ok = false;
                e++;
            }
        }
    }

    if ( d->messages.isEmpty() )
        return 0;

    uint i = d->messages.smallest();
    d->messages.remove( i );

    String f( d->path + "/" + String::fromNumber( i ) + "." );
    File m( f );
    MigratorMessage * mm = new MigratorMessage( m.contents(), f );
    if ( d->seen.contains( i ) )
        mm->addFlag( "\\seen" );
    return mm;
}
