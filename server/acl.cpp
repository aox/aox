// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "acl.h"

#include "mailbox.h"
#include "event.h"
#include "user.h"


/*! \class ACL acl.h
    The ACL class provides RFC 2086 access control lists.

    It can evaluate its list and provide the list of rights available
    for any given user.

    The rights are based on RFC 2086 (and its updated internet-draft)
    and are:

    Lookup ("l"): Mailbox is visible to LIST/LSUB commands, SUBSCRIBE
    mailbox. This is always granted to everyone, for the moment.

    Read ("r"): SELECT the mailbox, perform STATUS.

    KeepSeen ("s"): Keep seen/unseen information across sessions (set or
    clear "\SEEN" flag via STORE, also set "\SEEN" during
    APPEND/COPY/FETCH BODY[...]).

    Write ("w"): Set or clear flags other than "\SEEN" and "\DELETED" via
    STORE, also set them during APPEND/COPY).

    Insert ("i"): Perform APPEND, COPY into mailbox.

    Post ("p"): Send mail to submission address for mailbox, not
    enforced by IMAP4 itself.

    CreateMailboxes ("k"): CREATE new sub-mailboxes, or RENAME to a
    sub-mailbox of this mailbox.

    DeleteMailbox ("x"): DELETE mailbox, RENAME mailbox to something
    else.

    DeleteMessages ("t"): Set or clear "\DELETED" flag via STORE, set
    "\DELETED" flag during APPEND/COPY.

    Expunge ("e"): Perform EXPUNGE, and expunge as a part of CLOSE.

    Admin ("a"): Administer (perform SETACL/DELETEACL/GETACL). This is
    always granted to the owner of a mailbox, and may be granted to
    others.

    For the moment, this class cannot modify the database, it only
    interprets its current contents. Until it has updated itself from
    the database, ready() returns false. As soon as it's ready(),
    allowed() tells you whether a given user has a given right.

    refresh() requests that the ACL object refresh itself from the
    database and notify the specified event handler once it's ready.
*/


/*! Constructs an ACL object for \a mailbox and immedietely refreshes
    it from the database.

*/

ACL::ACL( Mailbox * mailbox )
    : d( 0 )
{
    mailbox = mailbox;
}


/*! Returns true if the ACL object is ready to answer questions using
    allowed(), and false the object is currently fetching data from
    the database.
*/

bool ACL::ready()
{
    return false;
}


/*! Returns true if \a u is permitted to do \a r by this ACL. */

bool ACL::allowed( User * u, Right r)
{
    u = u;
    r = r;
    return false;
}


/*! Starts refreshing this object from the database, and will notify
    \a handler as soon as it's done.

    refresh() may be called several times with different \a handler
    objects; all will be notified.
*/

void ACL::refresh( EventHandler * handler )
{
    handler = handler;
}
