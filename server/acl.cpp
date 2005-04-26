// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "acl.h"

#include "mailbox.h"
#include "event.h"
#include "query.h"
#include "user.h"


static char rightChar( ACL::Right );


class AclData {
public:
    AclData()
        : ready( false ), mailbox( 0 ), user( 0 ), owner( 0 ),
          allowed( false ), q( 0 )
    {}

    bool ready;
    Mailbox *mailbox;
    User *user;
    ACL::Right right;
    EventHandler *owner;
    bool allowed;
    Query *q;
};


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

    For the moment, this class cannot modify the database. It can only
    verify() that a user has a given right, and will notify an event
    handler when it's ready() to say whether the access is allowed()
    or not.
*/

/*! Constructs an ACL object for \a mailbox, but does nothing further
    until verify() is called.
*/

ACL::ACL( Mailbox *mailbox )
    : d( new AclData )
{
    d->mailbox = mailbox;
}


/*! Returns true if the ACL object is ready to answer the question using
    allowed(), and false the object is still fetching data.
*/

bool ACL::ready()
{
    return d->ready;
}


/*! Returns true only if the user has the Right specified in the call to
    verify(). This function is meaningful only when the ACL is ready().
*/

bool ACL::allowed()
{
    return d->allowed;
}


/*! Checks to see if the user \a u has the right \a r, and notifies the
    \a handler when allowed() can answer the question.
*/

void ACL::verify( User *u, Right r, EventHandler *handler )
{
    d->user = u;
    d->right = r;
    d->owner = handler;
    execute();
}


/*! This function processes ACL results from the database and calculates
    the applicable permissions.
*/

void ACL::execute()
{
    if ( !d->q ) {
        // The user and superuser always have all rights.
        if ( d->user->id() == d->mailbox->owner() ||
             0 /* d->user->isRoot() */ )
        {
            d->allowed = true;
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
        if ( rights.find( rightChar( d->right ) ) )
            d->allowed = true;
        else
            d->allowed = false;
    }

    d->ready = true;
    d->owner->execute();
}


static char rightChar( ACL::Right r )
{
    char c;
    switch ( r ) {
    case ACL::Lookup:
        c = 'l';
    case ACL::Read:
        c = 'r';
    case ACL::KeepSeen:
        c = 's';
    case ACL::Write:
        c = 'w';
    case ACL::Insert:
        c = 'i';
    case ACL::Post:
        c = 'p';
    case ACL::CreateMailboxes:
        c = 'k';
    case ACL::DeleteMailbox:
        c = 'x';
    case ACL::DeleteMessages:
        c = 't';
    case ACL::Expunge:
        c = 'e';
    case ACL::Admin:
        c = 'a';
    }
    return c;
}
