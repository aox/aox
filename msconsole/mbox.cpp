// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "mbox.h"

#include "stringlist.h"
#include "file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>


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


bool MboxDirectory::isMailbox( const String &path, struct stat *st )
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
    MboxMailboxData(): read( false ), offset( 0 ), msn( 1 ) {}

    String path;
    bool read;
    uint offset;
    String contents;
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
               d->contents.mid( i, 5 ) == "From " ) )
        i++;

    MigratorMessage * m
        = new MigratorMessage( d->contents.mid( d->offset,
                                                i - d->offset ),
                               d->path + ":" + fn( d->msn ) +
                               " (offset " + fn( d->offset ) + ")" );
    d->offset = i;
    d->msn++;

    return m;
}
