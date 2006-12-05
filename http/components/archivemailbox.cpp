// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "archivemailbox.h"

#include "link.h"


class ArchiveMailboxData
    : public Garbage
{
public:
    ArchiveMailboxData()
        : link( 0 )
    {}

    Link * link;
};


/*! \class ArchiveMailbox archivemailbox.h
    A page component representing a view of a single mailbox.
*/


/*! Create a new ArchiveMailbox for \a link. */

ArchiveMailbox::ArchiveMailbox( Link * link )
    : PageComponent( "archivemailbox" ),
      d( new ArchiveMailboxData )
{
    d->link = link;
}


void ArchiveMailbox::execute()
{
}
