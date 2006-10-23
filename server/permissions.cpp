// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "permissions.h"

#include "stringlist.h"
#include "mailbox.h"
#include "event.h"
#include "query.h"
#include "user.h"


const char * Permissions::rights = "lrswipkxtean";


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
        allowed[Permissions::Lookup] = true;
    }

    bool ready;
    Mailbox * mailbox;
    User * user;
    EventHandler * owner;
    bool allowed[ Permissions::NumRights ];
    Query * q;
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
        // The owner of a mailbox always has all rights.
        if ( d->user->login() != "anonymous" &&
             ( d->user->id() == d->mailbox->owner() ||
               d->user->home() == d->mailbox ||
               d->mailbox->name().startsWith( d->user->home()->name() +
                                              "/" ) ) )
        {
            uint i = 0;
            while ( i < Permissions::NumRights )
                d->allowed[i++] = true;
            // not even the owner can meaningfully append messages to a view
            if ( d->mailbox->view() )
                d->allowed[Insert] = false;
            // DeleteMessages and Expunge are dubious too... allow them
            // for the moment
            d->ready = true;
            return;
        }

        // We have to let the anonymous user read its inbox.
        if ( d->user->login() == "anonymous" &&
             d->user->inbox() == d->mailbox )
        {
            d->allowed[Read] = true;
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
            s.append( rightChar( r ) );
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

char Permissions::rightChar( Permissions::Right right )
{
    return rights[ (int)right ];
}


/*! Returns true only if \a c represents a valid right. */

bool Permissions::validRight( char c )
{
    if ( c == 'c' || c == 'd' || String( rights ).contains( c ) )
        return true;
    return false;
}


/*! Returns true only if \a s represents a valid set of rights. */

bool Permissions::validRights( const String &s )
{
    uint i = 0;
    String r( rights );
    while ( i < s.length() ) {
        if ( !validRight( s[i] ) )
            return false;
        i++;
    }
    return true;
}


/*! Returns a string containing all available rights characters. */

String Permissions::all()
{
    return String( rights ) + "cd";
}


/*! Sets this object's permitted rights to \a rights, and removes all
    other rights.
*/

void Permissions::set( const String &rights )
{
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        bool v = false;
        if ( rights.contains( rightChar( (Right)i ) ) )
            v = true;
        d->allowed[i] = v;
        i++;
    }

    if ( rights.contains( 'c' ) )
        d->allowed[(int)CreateMailboxes] = true;

    if ( rights.contains( 'd' ) ) {
        d->allowed[(int)Expunge] = true;
        d->allowed[(int)DeleteMessages] = true;
        d->allowed[(int)DeleteMailbox] = true;
    }

    d->allowed[(int)Lookup] = true;
}


/*! This function adds the specified \a rights to this object.
    Any unrecognised right characters are ignored.
*/

void Permissions::allow( const String &rights )
{
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        if ( rights.contains( rightChar( (Right)i ) ) )
            d->allowed[i] = true;
        i++;
    }

    if ( rights.contains( 'c' ) )
        d->allowed[(int)CreateMailboxes] = true;

    if ( rights.contains( 'd' ) ) {
        d->allowed[(int)Expunge] = true;
        d->allowed[(int)DeleteMessages] = true;
        d->allowed[(int)DeleteMailbox] = true;
    }
}


/*! This function removes the specified \a rights from this object.
    Any unrecognised right characters are ignored.
*/

void Permissions::disallow( const String &rights )
{
    uint i = 0;
    while ( i < Permissions::NumRights ) {
        if ( rights.contains( rightChar( (Right)i ) ) )
            d->allowed[i] = false;
        i++;
    }

    if ( rights.contains( 'c' ) )
        d->allowed[(int)CreateMailboxes] = false;

    if ( rights.contains( 'd' ) ) {
        d->allowed[(int)Expunge] = false;
        d->allowed[(int)DeleteMessages] = false;
        d->allowed[(int)DeleteMailbox] = false;
    }

    d->allowed[(int)Lookup] = true;
}


/*! Returns a pointer to the mailbox for which this object remembers rights. */

Mailbox * Permissions::mailbox() const
{
    return d->mailbox;
}


/*! Returns a pointer to the user for which this object remembers rights. */

User * Permissions::user() const
{
    return d->user;
}


/*! \class PermissionsChecker permissions.h

    The PermissionsChecker class is a convenience mangler. It collects
    a set of Permissions and Permissions::Right objects, and checks
    that all are allowed. If not, it generates a suitable error message.
*/


class PermissionsCheckerData
    : public Garbage
{
public:
    PermissionsCheckerData(): Garbage() {}
    struct Pair
        : public Garbage
    {
        Pair(): p( 0 ), r( Permissions::Lookup ) {}
        Permissions * p;
        Permissions::Right r;
    };
    List<Pair> l;
};


/*!  Constructs an empty PermissionsChecker. Pretty much a noop. */

PermissionsChecker::PermissionsChecker()
    : Garbage(), d( new PermissionsCheckerData )
{
}


/*! Notes that this object's user requires \a r on \a p. */

void PermissionsChecker::require( Permissions * p, Permissions::Right r )
{
    List<PermissionsCheckerData::Pair>::Iterator i( d->l );
    while ( i ) {
        if ( i->p == p && i->r == r )
            return;
        ++i;
    }
    
    PermissionsCheckerData::Pair * pair = new PermissionsCheckerData::Pair;
    pair->p = p;
    pair->r = r;
    d->l.append( pair );
}


/*! Returns true if all all Permissions objects specified using
    require() allow the relevant right, and false in all other cases.
*/

bool PermissionsChecker::allowed() const
{
    List<PermissionsCheckerData::Pair>::Iterator i( d->l );
    while ( i ) {
        if ( !i->p->ready() || !i->p->allowed( i->r ) )
            return false;
        ++i;
    }
    return true;
}


/*! Returns true if this checker can return a valid result, and false
    if at least one Permissions object still doesn't have the data it
    needs.
*/

bool PermissionsChecker::ready() const
{
    List<PermissionsCheckerData::Pair>::Iterator i( d->l );
    while ( i ) {
        if ( !i->p->ready() )
            return false;
        ++i;
    }
    return true;
}


static const char * rightNames[Permissions::NumRights] = {
    "Lookup", // l
    "Read", // r
    "Keep Seen", // s
    "Write", // w
    "Insert", // i
    "Post", // p
    "Create Mailboxes", // k
    "Delete Mailbox", // x
    "Delete Messages", // t
    "Expunge", // e
    "Admin", // a
    "Write Shared Annotation", // n
};


/*! Returns an error string describing the missing permissions. If
    allowed() returns true, this is an empty string. If allowed() is
    false, it is a long, perhaps multi-line string.
    
    If ready() returns false, this function returns an almost random
    string.
*/

String PermissionsChecker::error() const
{
    StringList l;
    List<PermissionsCheckerData::Pair>::Iterator i( d->l );
    while ( i ) {
        if ( !i->p->allowed( i->r ) )
            l.append( "Not permitted. Mailbox: " + i->p->mailbox()->name() +
                      " Missing right: " + rightNames[i->r] );
        ++i;
    }
    return l.join( "\r\n" );
}


/*! Returns a Permissions object for \a m, \a u if this
    PermissionsChecker happens to have one, and returns a null pointer
    if it doesn't.
*/

Permissions * PermissionsChecker::permissions( class Mailbox * m, class User * u ) const
{
    List<PermissionsCheckerData::Pair>::Iterator i( d->l );
    while ( i && ( i->p->mailbox() != m || i->p->user() != u ) )
        ++i;
    if ( i )
        return i->p;
    return 0;
}
