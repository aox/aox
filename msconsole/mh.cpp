// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mh.h"

#include "file.h"

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
