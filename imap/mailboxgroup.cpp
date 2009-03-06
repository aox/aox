// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailboxgroup.h"

#include "mailbox.h"
#include "map.h"


class MailboxGroupData
    : public Garbage
{
public:
    MailboxGroupData(): hits( 0 ), misses( 0 ) {}

    Map<Mailbox> mailboxes;
    uint hits;
    uint misses;
};


/*! \class MailboxGroup mailboxgroup.h

    The MailboxGroup class models a client's group of mailboxes,
    including the likelihood that the client actually has such a
    group.

    Many clients like to perform the same operation on many
    mailboxes. In order to limit load and improve performance,
    Archiveopteryx tries to detect that and restructure the work done.

    An instance of this class is created when Archiveopteryx thinks
    that such an operation may be starting. When a mailbox operation
    is performed on something this object contains(), a user can check
    the number of hits() and if deemed large enough, it may choose to
    process the remaining contents() in advance and cache the results.
*/



/*!  Constructs a group of \a mailboxes. */

MailboxGroup::MailboxGroup( List<Mailbox> * mailboxes )
    : d( new MailboxGroupData )
{
    List<Mailbox>::Iterator i( mailboxes );
    while ( i ) {
        d->mailboxes.insert( i->id(), i );
        ++i;
    }
}


/*! Returns true if this group contains \a m, and false if not,
    updates the hits() and misses() counters, and removes \a m from
    this group if present.
*/

bool MailboxGroup::contains( const Mailbox * m )
{
    bool c = d->mailboxes.contains( m->id() );
    if ( c ) {
        d->hits++;
        d->mailboxes.remove( m->id() );
    }
    else {
        d->misses++;
    }
    return c;
}


/*! Returns the number of times recordHit() has been called. */

uint MailboxGroup::hits() const
{
    return d->hits;
}


/*! Returns the number of times recordMiss() has been called. */

uint MailboxGroup::misses() const
{
    return d->misses;
}


/*! Returns a list containing the mailboxes (still) in this group. The
    list may be empty, but will not be null.

    Note that when contains() returns true it removes its mailbox, so
    contents() will not return a just-tested mailbox.
*/

List<Mailbox> * MailboxGroup::contents() const
{
    List<Mailbox> * r = new List<Mailbox>;
    Map<Mailbox>::Iterator i( d->mailboxes );
    while ( i ) {
        r->append( i );
        ++i;
    }
    return r;
}
