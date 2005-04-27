// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "permissions.h"

#include "mailbox.h"
#include "event.h"
#include "query.h"
#include "user.h"


static char rightChar( Permissions::Right );


class PermissionData {
public:
    PermissionData()
        : ready( false ), mailbox( 0 ), user( 0 ), owner( 0 ), q( 0 )
    {
        uint i = 0;
        while ( i < Permissions::NumRights )
            allowed[i++] = false;
    }

    bool ready;
    Mailbox *mailbox;
    User *user;
    EventHandler *owner;
    bool allowed[ Permissions::NumRights ];
    Query *q;
};


/*! \class Permissions permissions.h
    This class provides RFC 2086 access control lists.

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

    For the moment, this class cannot modify the database. It can only
    verify that a user has a given right, and will notify an event
    handler when it's ready() to say whether the access is allowed()
    or not.
*/

/*! Constructs an Permissions object for \a mailbox and \a user, and
    calls execute() to calculate permissions, issuing queries if
    necessary. If any queries are needed, \a handler will be notified
    when the object is ready().
*/

Permissions::Permissions( Mailbox *mailbox, User *user,
                          EventHandler *handler )
    : d( new PermissionData )
{
    d->mailbox = mailbox;
    d->user = user;
    d->owner = handler;
    execute();
}


/*! Returns true if the ACL object is ready to answer the question using
    allowed(), and false the object is still fetching data.
*/

bool Permissions::ready()
{
    return d->ready;
}


/*! Returns true only if the user has the \a r Right. This function is
    meaningful only when the object is ready().
*/

bool Permissions::allowed( Right r )
{
    return d->allowed[r];
}


/*! This function processes ACL results from the database and calculates
    the applicable permissions.
*/

void Permissions::execute()
{
    if ( !d->q ) {
        // The user and superuser always have all rights.
        if ( d->user->id() == d->mailbox->owner() ||
             d->user->inbox()->id() == d->mailbox->id() ||
             0 /* d->user->isRoot() */ )
        {
            uint i = 0;
            while ( i < Permissions::NumRights )
                d->allowed[i++] = true;
            d->ready = true;
            return;
        }

        // For everyone else, we have to check.
        d->q = new Query( "select * from permissions where mailbox=$1 and "
                          "identifier=$2", this );
        d->q->bind( 1, d->mailbox->id() );
        d->q->bind( 2, d->user->login() );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    while ( d->q->hasResults() ) {
        Row *r = d->q->nextRow();

        String rights;
        if ( !r->isNull( "rights" ) )
            rights = r->getString( "rights" );

        uint i = 0;
        while ( i < Permissions::NumRights ) {
            int n = rights.find( rightChar( (Permissions::Right)i ) );
            if ( n >= 0 )
                d->allowed[i] = true;
        }
    }

    d->ready = true;
    d->owner->execute();
}


static char rightChar( Permissions::Right r )
{
    char c;
    switch ( r ) {
    case Permissions::Lookup:
        c = 'l';
        break;
    case Permissions::Read:
        c = 'r';
        break;
    case Permissions::KeepSeen:
        c = 's';
        break;
    case Permissions::Write:
        c = 'w';
        break;
    case Permissions::Insert:
        c = 'i';
        break;
    case Permissions::Post:
        c = 'p';
        break;
    case Permissions::CreateMailboxes:
        c = 'k';
        break;
    case Permissions::DeleteMailbox:
        c = 'x';
        break;
    case Permissions::DeleteMessages:
        c = 't';
        break;
    case Permissions::Expunge:
        c = 'e';
        break;
    case Permissions::Admin:
        c = 'a';
        break;
    case Permissions::NumRights:
        c = '\0';
        break;
    }
    return c;
}
