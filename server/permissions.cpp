// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "permissions.h"

#include "stringlist.h"
#include "mailbox.h"
#include "event.h"
#include "query.h"
#include "user.h"


static char * rights = "lrswipkxtean";


class PermissionData
    : public Garbage
{
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

    The rights are based on RFC 2086, its updated internet-draft and
    the ANNOTATE draft. The rights are:

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
    
    WriteSharedAnnotation ("n"): Write a shared annotation. This is
    always granted to the mailbox owner, and may be granted to others.

    For the moment, this class cannot modify the database. It can only
    verify that a user has a given right, and will notify an event
    handler when it's ready() to say whether the access is allowed()
    or not.
*/

/*! Constructs a Permissions object for \a mailbox and \a authid with
    the specified \a rights.
*/

Permissions::Permissions( Mailbox * mailbox, const String &authid,
                          const String &rights )
    : d( new PermissionData )
{
    d->mailbox = mailbox;
    d->user = new User;
    d->user->setLogin( authid );
    set( rights );
}


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
             d->user->home() == d->mailbox ||
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
        d->q = new Query( "select * from permissions "
                          "where mailbox=$1 and "
                          "(identifier=$2 or identifier='anyone')",
                          this );
        d->q->bind( 1, d->mailbox->id() );
        d->q->bind( 2, d->user->login() );
        d->q->execute();
    }

    if ( !d->q->done() )
        return;

    while ( d->q->hasResults() ) {
        Row * r = d->q->nextRow();
        if ( !r->isNull( "rights" ) )
            allow( r->getString( "rights" ) );
    }

    d->ready = true;
    d->owner->execute();
}


/*! Returns a string representation of this ACL entry, suitable for use
    in a MYRIGHTS response.

    (This is subject to change.)
*/

String Permissions::string() const
{
    String s;

    bool cr = false;
    bool dr = false;

    uint i = 0;
    while ( i < Permissions::NumRights ) {
        if ( d->allowed[i] ) {
            Right r = (Right)i;
            if ( r == CreateMailboxes )
                cr = true;
            else if ( r == DeleteMailbox || r == DeleteMessages ||
                      r == Expunge )
                dr = true;
            s.append( charredRight( r ) );
        }
        i++;
    }

    if ( cr )
        s.append( "c" );
    if ( dr )
        s.append( "d" );

    if ( s.isEmpty() )
        s = "\"\"";

    return s;
}


/*! This static helper returns the RFC 2086 name for \a right. */

char Permissions::charredRight( Permissions::Right right )
{
    return ::rights[ (int)right ];
}


/*! Returns the right corresponding to \a c. This function should be
    called only if \a c is a validRight().
*/

Permissions::Right Permissions::rightedChar( char c )
{
    return (Right)String( ::rights ).find( c );
}


/*! Returns true only if \a c represents a valid right. */

bool Permissions::validRight( char c )
{
    return String( ::rights ).find( c ) >= 0;
}


/*! Returns true only if \a s represents a valid set of rights. */

bool Permissions::validRights( const String &s )
{
    uint i = 0;
    String r( ::rights );
    while ( i < s.length() ) {
        if ( r.find( s[i] ) < 0 )
            return false;
        i++;
    }
    return true;
}


/*! Returns a string containing all available rights characters. */

String Permissions::all()
{
    return String( ::rights ) + "cd";
}


/*! Sets this object's permitted rights to \a rights, and removes all
    other rights.
*/

void Permissions::set( const String &rights )
{
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        bool v = false;
        if ( rights.find( charredRight( (Right)i ) ) >= 0 )
            v = true;
        d->allowed[i] = v;
        i++;
    }
}


/*! This function adds the specified \a rights to this object.
    Any unrecognised right characters are ignored.
*/

void Permissions::allow( const String &rights )
{
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        if ( rights.find( charredRight( (Right)i ) ) >= 0 )
            d->allowed[i] = true;
        i++;
    }
}


/*! This function removes the specified \a rights from this object.
    Any unrecognised right characters are ignored.
*/

void Permissions::disallow( const String &rights )
{
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        if ( rights.find( charredRight( (Right)i ) ) >= 0 )
            d->allowed[i] = false;
        i++;
    }
}
