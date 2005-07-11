// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mh.h"

#include "file.h"
#include "stringlist.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>


class MhMailboxData {
public:
    MhMailboxData()
        : opened( false ), dir( 0 )
    {}

    bool opened;
    String path;
    DIR *dir;
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

MigratorMessage *MhMailbox::nextMessage()
{
    if ( !d->opened ) {
        d->opened = true;
        String mh( d->path + "/.mh_sequences" );
        struct stat st;
        if ( ::stat( mh.cstr(), &st ) < 0 )
            return 0;
        d->dir = ::opendir( d->path.cstr() );
    }

    if ( !d->dir )
        return 0;

    struct dirent *de = ::readdir( d->dir );
    while ( de ) {
        if ( de->d_name[0] == '.' ||
             de->d_name[0] == ',' )
        {
            // We ignore ,-prefixed names, but should we import them and
            // set \Deleted instead?
            de = ::readdir( d->dir );
        }
        else {
            // Do we need to check that the name is all-numerals?
            // Do we need to sort messages?
            String f( d->path + "/" + de->d_name );
            File m( f );
            return new MigratorMessage( m.contents(), f );
        }
    }

    ::closedir( d->dir );
    d->dir = 0;
    return 0;
}



class MhDirectoryData {
public:
    MhDirectoryData()
        : prefixLength( 0 )
    {}

    StringList paths;
    uint prefixLength;
};


/*! \class MhDirectory mh.h

    Represents a hierarchy of directories and MH mailboxes. It hands out
    the name of each mailbox in turn using the MigratorSource API.
*/


/*! Constructs an MhDirectory for \a path.
*/

MhDirectory::MhDirectory( const String &path )
    : d( new MhDirectoryData )
{
    if ( path.length() > 0 && path[path.length()-1] == '/' )
        d->paths.append( path.mid( 0, path.length()-1 ) );
    else
        d->paths.append( path );
    d->prefixLength = d->paths.first()->length();
}


MhMailbox *MhDirectory::nextMailbox()
{
    String *p = 0;

    while ( !p ) {
        if ( d->paths.isEmpty() )
            return 0;

        p = d->paths.shift();

        struct stat st;
        if ( stat( p->cstr(), &st ) < 0 ) {
            p = 0;
        }
        else if ( S_ISDIR( st.st_mode ) ) {
            DIR *dp = opendir( p->cstr() );
            if ( dp ) {
                struct dirent *de = readdir( dp );
                while ( de ) {
                    if ( !( de->d_name[0] == '.' &&
                            ( de->d_name[1] == '\0' ||
                              ( de->d_name[1] == '.' &&
                                de->d_name[2] == '\0' ) ) ) )
                    {
                        String * tmp = new String;
                        uint len = strlen( de->d_name );
                        tmp->reserve( p->length() + 1 + len );
                        tmp->append( *p );
                        tmp->append( "/" );
                        tmp->append( de->d_name, len );
                        d->paths.append( tmp );
                    }
                    de = readdir( dp );
                }
                closedir( dp );

                // Is this directory an MH mailbox?
                String s( *p + "/.mh_sequences" );
                if ( stat( s.cstr(), &st ) < 0 )
                    p = 0;
            }
            else {
                p = 0;
            }
        }
    }
    if ( !p )
        return 0;
    return new MhMailbox( *p, d->prefixLength );
}
