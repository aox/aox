// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
    MessageSet unseen;
    MessageSet flagged;
};


/*! \class MhMailbox mh.h

    This class models an MH mailbox: a directory full of numbered
    files, each containing one message. A directory is identified as a
    valid MH mailbox by the presence of an .mh_sequences file. At this
    time, only files whose names do not begin with a comma are
    considered. The messages are imported in numeric order and
    compacted (the smallest becomes 1, etc).
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
        File sequences( d->path + "/.mh_sequences", File::Read );
        StringList::Iterator l( sequences.lines() );
        while ( l ) {
            if ( l->startsWith( "unseen:" ) )
                addToSet( *l, &d->unseen );
            else if ( l->startsWith( "picked:" ) )
                addToSet( *l, &d->flagged );
            ++l;
        }
    }

    if ( d->messages.isEmpty() )
        return 0;

    uint i = d->messages.smallest();
    d->messages.remove( i );

    String f( d->path + "/" + String::fromNumber( i ) );
    File m( f );
    MigratorMessage * mm = new MigratorMessage( m.contents(), f );
    if ( !d->unseen.contains( i ) )
        mm->addFlag( "\\seen" );
    if ( d->flagged.contains( i ) )
        mm->addFlag( "\\flagged" );
    return mm;
}


/*! Adds the messages specified in \a line to \a set. Aborts
    (silently) on any error.  \a line must contain a word, a colon,
    and a series of space-separated numbers or ranges. The word is
    disregarded.
*/

void MhMailbox::addToSet( const String &line, class MessageSet * set )
{
    uint e = 0;
    while ( e < line.length() && line[e] != ':' )
        e++;
    while ( line[e] == ' ' || line[e] == ':' )
        e++;
    bool ok = true;
    while ( ok && e < line.length() ) {
        uint b = e;
        while ( line[e] >= '0' && line[e] <= '9' )
            e++;
        uint first = line.mid( b, e-b ).number( &ok );
        uint second = first;
        if ( line[e] == '-' ) {
            e++;
            b = e;
            while ( line[e] >= '0' && line[e] <= '9' )
                e++;
            second = line.mid( b, e-b ).number( &ok );
        }
        if ( line[e] == ' ' || e >= line.length() )
            set->add( first, second );
        else
            ok = false;
        e++;
    }
}
