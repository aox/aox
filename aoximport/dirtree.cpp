// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "dirtree.h"

#include "sys.h"
#include "file.h"
#include "stringlist.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>


class DirectoryTreeData
    : public Garbage
{
public:
    DirectoryTreeData()
        : prefixLength( 0 )
    {}

    StringList paths;
    uint prefixLength;
};


/*! \class DirectoryTree dirtree.h

    Represents a directory tree from which subclasses can pick out the
    entries that represent viable mailboxes.
*/


/*! Constructs a DirectoryTree rooted at \a path. */

DirectoryTree::DirectoryTree( const String &path )
    : d( new DirectoryTreeData )
{
    if ( path.length() > 0 && path[path.length()-1] == '/' )
        d->paths.append( path.mid( 0, path.length()-1 ) );
    else
        d->paths.append( path );
    d->prefixLength = d->paths.first()->length();
}


/*! Recursively examines each entry in this DirectoryTree to find valid
    mailboxes. Returns a pointer to a MigratorMailbox object, or 0 if
    there are no more mailboxes under this tree.

    This function depends on the implementation of isMailbox() and
    newMailbox() by subclasses.
*/

MigratorMailbox * DirectoryTree::nextMailbox()
{
    String *p = 0;

    while ( !p ) {
        if ( d->paths.isEmpty() )
            return 0;

        p = d->paths.shift();

        struct stat st;
        int n = ::stat( p->cstr(), &st );
        if ( n < 0 ) {
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
            }
        }
        if ( n < 0 || !isMailbox( *p, &st ) )
            p = 0;
    }

    if ( !p )
        return 0;

    return newMailbox( *p, d->prefixLength );
}


/*! \fn bool DirectoryTree::isMailbox( const String &p, struct stat *st )

    Returns true if \a p (described by the stat results in \a st) is a
    valid Mailbox, and false if it should be ignored. This function is
    called by nextMailbox().
*/


/*! \fn MigratorMailbox * DirectoryTree::newMailbox( const String &fn,
                                                     uint prefixLength )

    Returns a pointer to a new MigratorMailbox created from \a fn, the
    first \a prefixLength bytes of which are not considered in naming
    the mailbox. This function is called by nextMailbox() for every
    file or directory that isMailbox().
*/
