// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailbox.h"

#include "log.h"
#include "map.h"
#include "dict.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "event.h"
#include "string.h"
#include "message.h"
#include "fetcher.h"
#include "session.h"
#include "threader.h"
#include "allocator.h"
#include "messageset.h"
#include "stringlist.h"
#include "transaction.h"


class MailboxData
    : public Garbage
{
public:
    MailboxData()
        : type( Mailbox::Synthetic ), id( 0 ),
          uidnext( 0 ), uidvalidity( 0 ), owner( 0 ),
          parent( 0 ), children( 0 ),
          sessions( 0 ), threader( 0 ),
          nextModSeq( 1 ),
          source( 0 ),
          views( 0 )
    {}

    UString name;

    Mailbox::Type type;

    uint id;
    uint uidnext;
    uint uidvalidity;
    uint owner;

    Mailbox * parent;
    List< Mailbox > * children;
    List<Session> * sessions;
    Threader * threader;

    int64 nextModSeq;

    uint source;
    String selector;

    List<Mailbox> * views;
};


static Mailbox * root = 0;
static Map<Mailbox> * mailboxes = 0;


/*! \class Mailbox mailbox.h
    This class represents a node in the global mailbox hierarchy.

    Every Mailbox has a unique name() within the hierarchy. Any
    Mailbox that can contain messages has a non-zero numeric id() and
    attributes like uidvalidity() and uidnext(). Mailboxes have a
    parent() and may have a number of children().

    Some mailboxes aren't quite real. A Mailbox can be deleted(), in
    which case it can contain no messags. If recreated, a deleted()
    mailbox preserves its uidvalidity() and uid series. It can also be
    synthetic(), meaning that it exists only in RAM, not in the database.

    This class maintains a tree of mailboxes, based on the contents of
    the mailboxes table and descriptive messages from the OCServer. It
    can find() a named mailbox in this hierarchy. Synthetic messages
    are internal nodes in the tree, necessary to connect the root to
    the leaves.
*/


class MailboxReader
    : public EventHandler
{
public:
    EventHandler * owner;
    Query * query;

    MailboxReader( EventHandler * ev )
        : owner( ev ), query( 0 )
    {
        query =
            new Query( "select m.*,source,view,v.nextmodseq as viewnms,"
                       "selector from "
                       "mailboxes m left join views v on (m.id=v.view)",
                       this );
    }


    MailboxReader( const UString & n )
        : owner( 0 ), query( 0 )
    {
        query =
            new Query( "select m.*,source,view,v.nextmodseq as viewnms,"
                       "selector from "
                       "mailboxes m left join views v on (m.id=v.view) "
                       "where name=$1", this );
        query->bind( 1, n );
    }


    void execute() {
        while ( query->hasResults() ) {
            Row * r = query->nextRow();

            UString n = r->getUString( "name" );
            Mailbox * m = Mailbox::obtain( n );
            if ( n != m->d->name )
                m->d->name = n;
            m->setId( r->getInt( "id" ) );

            if ( r->getBoolean( "deleted" ) )
                m->setType( Mailbox::Deleted );
            else if ( r->isNull( "view" ) )
                m->setType( Mailbox::Ordinary );
            else
                m->setType( Mailbox::View );

            m->d->uidvalidity = r->getInt( "uidvalidity" );
            m->setUidnextAndNextModSeq( r->getInt( "uidnext" ),
                                        r->getBigint( "nextmodseq" ) );
            if ( !r->isNull( "owner" ) )
                m->setOwner( r->getInt( "owner" ) );

            if ( m->type() == Mailbox::View ) {
                m->d->source = r->getInt( "source" );
                m->d->nextModSeq = r->getBigint( "viewnms" );
                m->d->selector = r->getString( "selector" );
            }

            if ( m->d->id )
                ::mailboxes->insert( m->d->id, m );
        }

        if ( query->done() && owner ) {
            if ( query->failed() )
                log( "Couldn't create mailbox tree: " + query->error(),
                     Log::Disaster );
            owner->execute();
        }
    }
};


/*! This static function is responsible for building a tree of
    Mailboxes from the contents of the mailboxes table. It expects to
    be called by ::main().

    If \a owner is non-null (the default is null), this function calls
    EventHandler::waitFor() on \a owner to wait for setup to complete.
*/

void Mailbox::setup( EventHandler * owner )
{
    UString r;
    r.append( '/' );
    ::root = new Mailbox( r );
    Allocator::addEternal( ::root, "root mailbox" );

    ::mailboxes = new Map<Mailbox>;
    Allocator::addEternal( ::mailboxes, "mailbox tree" );

    MailboxReader * mr = new MailboxReader( owner );
    if ( owner )
        owner->waitFor( mr->query );
    mr->query->execute();
}


/*! This function reloads this mailbox from the database. If \a owner is
    specified, it is used to set the new MailboxReader's owner.
    (This is still a hack.)
*/

Query * Mailbox::refresh( EventHandler * owner )
{
    MailboxReader * mr = new MailboxReader( name() );
    mr->owner = owner;
    return mr->query;
}


/*! Creates a Mailbox named \a name. This constructor is only meant to
    be used via Mailbox::obtain(). */

Mailbox::Mailbox( const UString &name )
    : d( new MailboxData )
{
    d->name = name;
}


/*! Returns the fully qualified name of this Mailbox. */

UString Mailbox::name() const
{
    return d->name;
}


/*! Sets the type of this Mailbox to \a t. The initial value is
    Synthetic (because it has to be something).
*/

void Mailbox::setType( Type t )
{
    d->type = t;
}


/*! Returns the type of this Mailbox. May be Synthetic, Ordinary,
    Deleted, or View.
*/

Mailbox::Type Mailbox::type() const
{
    return d->type;
}


/*! Returns the database ID of this Mailbox, or 0 if this Mailbox is
    synthetic().
*/

uint Mailbox::id() const
{
    return d->id;
}


/*! Notifies this Mailbox that its database ID is \a i. If \a i is 0,
    the Mailbox is synthetic.
*/

void Mailbox::setId( uint i ) const
{
    d->id = i;
}


/*! Returns the next UID value that will be used for this mailbox. */

uint Mailbox::uidnext() const
{
    return d->uidnext;
}


/*! Notifies this Mailbox that its correct uidvalidity is \a i. Should
    generally not be called.
*/

void Mailbox::setUidvalidity( uint i )
{
    d->uidvalidity = i;
}


/*! Returns the UIDVALIDITY value of this Mailbox. This never changes. */

uint Mailbox::uidvalidity() const
{
    return d->uidvalidity;
}


/*! Returns true if this Mailbox has been synthesized in-RAM in order
    to fully connect the mailbox tree, and false if the Mailbox exists
    in the database.
*/

bool Mailbox::synthetic() const
{
    return d->type == Synthetic;
}


/*! Returns true if this mailbox isn't "special". */

bool Mailbox::ordinary() const
{
    return d->type == Ordinary;
}


/*! Returns true if this mailbox is currently deleted. */

bool Mailbox::deleted() const
{
    return d->type == Deleted;
}


/*! Returns true if this mailbox is really a view. */

bool Mailbox::view() const
{
    return d->type == View;
}


/*! Returns true if this Mailbox represents a user's "home directory",
    e.g. /users/ams. (This is currently determined only by looking at
    the mailbox name, but it should be based on a flag that is set by
    the tree builder.)
*/

bool Mailbox::isHome() const
{
    if ( d->name.startsWith( "/users/" ) &&
         d->name.find( '/', 7 ) == -1 )
        return true;
    return false;
}


/*! Returns the numeric user id of the owner of this mailbox, or 0 if
    the mailbox has no defined owner (or is not yet known to have one).
*/

uint Mailbox::owner() const
{
    return d->owner;
}


/*! Returns a pointer to the parent of this Mailbox, or 0 if it is the
    root Mailbox.
*/

Mailbox *Mailbox::parent() const
{
    return d->parent;
}


/*! Returns a pointer to a List of this Mailbox's children, or 0 if it
    has none.
*/

List< Mailbox >* Mailbox::children() const
{
    return d->children;
}


/*! Returns true if this mailbox has at least one real, existing child
    mailbox, including indirect children, and false if not.
*/

bool Mailbox::hasChildren() const
{
    List<Mailbox>::Iterator it( d->children );
    while ( it ) {
        if ( !it->deleted() && !it->synthetic() )
            return true;
        if ( it->hasChildren() )
            return true;
        ++it;
    }
    return false;
}


/*! Returns a pointer to the source Mailbox that this View is based on,
    or 0 if this Mailbox is not a View.
*/

Mailbox * Mailbox::source() const
{
    return Mailbox::find( d->source );
}


/*! Returns the text of the selector that defines this view, or an empty
    string if this is not a View.
*/

String Mailbox::selector() const
{
    return d->selector;
}


/*! Returns a pointer to the Mailbox object at the root of the global
    hierarchy.
*/

Mailbox *Mailbox::root()
{
    return ::root;
}


/*! Returns a pointer to the Mailbox with \a id, or a null pointer if
    there is no such (known) Mailbox.

    Deleted mailboxes are included in the search, but synthetic ones
    aren't.
*/

Mailbox * Mailbox::find( uint id )
{
    if ( !::mailboxes )
        return 0;
    return ::mailboxes->find( id );
}


/*! Returns a pointer to a Mailbox named \a name, or 0 if the named
    mailbox doesn't exist. If \a deleted is true, deleted mailboxes
    are included in the search. The \a name must be fully-qualified.
*/

Mailbox * Mailbox::find( const UString &name, bool deleted )
{
    Mailbox * m = obtain( name, false );
    if ( !m )
        return 0;
    if ( m->deleted() && !deleted )
        return 0;
    if ( m->synthetic() )
        return 0;
    return m;
}


/*! Returns a pointer to the closest existing parent mailbox for \a
    name, or a null pointer if \a name doesn't look like a mailbox
    name at all, or if no parent mailboxes of \a name exist.

    Never returns a null pointer or a pointer to a nonexistent mailbox.
*/

Mailbox * Mailbox::closestParent( const UString & name )
{
    if ( name[0] != '/' )
        return 0;

    Mailbox * candidate = ::root;
    Mailbox * good = ::root;
    uint i = 1;
    while ( candidate && candidate->name() != name ) {
        if ( candidate && !candidate->deleted() &&
             ( !candidate->synthetic() || candidate->isHome() ) )
            good = candidate;
        if ( name[i] == '/' )
            return 0; // two slashes -> syntax error
        while ( i < name.length() && name[i] != '/' )
            i++;
        if ( !candidate->children() ) {
            candidate = 0;
        }
        else {
            UString next = name.mid( 0, i ).titlecased();
            List<Mailbox>::Iterator it( candidate->children() );
            while ( it && it->name().titlecased() != next )
                ++it;
            candidate = it;
            i++;
       }
    }
    return good;
}


/*! Obtain a mailbox with \a name, creating Mailbox objects as
    necessary and permitted.

    if \a create is true (this is the default) and there is no such
    Mailbox, obtain() creates one, including any necessary parents.
    The new mailbox is initially synthetic().

    If \a create is false and there is no such Mailbox, obtain()
    returns null without creating anything.
*/

Mailbox * Mailbox::obtain( const UString & name, bool create )
{
    if ( name[0] != '/' )
        return 0;

    uint i = name.length();
    while ( i > 0 && name[i] != '/' )
        i--;
    Mailbox * parent = ::root;
    if ( i > 0 )
        parent = obtain( name.mid( 0, i ), create );
    else if ( ::root->name() == name )
        return ::root;
    if ( !parent )
        return 0;
    if ( !create && !parent->children() )
        return 0;

    if ( !parent->d->children )
        parent->d->children = new List<Mailbox>;
    List<Mailbox>::Iterator it( parent->d->children );
    UString title = name.titlecased();
    UString candidate;
    if ( it )
        candidate = it->name().titlecased();
    while ( it && candidate < title ) {
        ++it;
        if ( it )
            candidate = it->name().titlecased();
    }
    if ( candidate == title )
        return it;
    if ( !create )
        return 0;

    Mailbox * m = new Mailbox( name );
    m->d->parent = parent;
    parent->d->children->insert( it, m );
    return m;
}


/*! Sets this Mailbox's owner to \a n (which is assumed to be a valid
    user id).
*/

void Mailbox::setOwner( uint n )
{
    d->owner = n;
}


/*! Changes this Mailbox's uidnext value to \a n. No checks are
    performed - although uidnext should monotonically increase, this
    function gives you total liberty.

    Only OCClient is meant to call this function. Calling it elsewhere
    will likely disturb either OCClient, ocd, ImapSession or Arnt.
*/

void Mailbox::setUidnext( uint n )
{
    if ( n == d->uidnext )
        return;
    d->uidnext = n;
    notifySessions();
}


/*! Atomically sets both uidnext() to \a n and nextModSeq() to \a m,
    so there's no chance notifySessions() might be called between the
    two changes.
*/

void Mailbox::setUidnextAndNextModSeq( uint n, int64 m )
{
    if ( n == d->uidnext && m == d->nextModSeq )
        return;
    d->uidnext = n;
    d->nextModSeq = m;
    notifySessions();
}


/*! Changes this Mailbox's deletedness to \a del.

    Only OCClient is *meant* to call this function -- see setUidnext().
    But don't check to see if that's really true.
*/

void Mailbox::setDeleted( bool del )
{
    if ( del )
        d->type = Deleted;
    else
        d->type = Ordinary;
}


/*! If this Mailbox does not exist, this function enqueues a Query to
    create it in the Transaction \a t and returns the Query. Otherwise
    it returns 0 and does nothing. It does not commit the transaction.

    If \a owner is non-null, the new mailbox is owned by by \a owner.
*/

Query * Mailbox::create( Transaction * t, User * owner )
{
    Query * q;

    if ( deleted() ) {
        q = new Query( "update mailboxes "
                       "set deleted='f',owner=$2,first_recent=uidnext "
                       "where id=$1", 0 );
        q->bind( 1, id() );
    }
    else if ( id() == 0 ) {
        q = new Query( "insert into mailboxes "
                       "(name,owner,uidnext,uidvalidity,deleted) "
                       "values ($1,$2,1,1,'f')", 0 );
        q->bind( 1, name() );
    }
    else {
        return 0;
    }

    if ( owner )
        q->bind( 2, owner->id() );
    else
        q->bindNull( 2 );

    t->enqueue( q );

    MailboxReader * mr = new MailboxReader( name() );
    t->enqueue( mr->query );

    return q;
}


/*! If this Mailbox can be deleted, this function enqueues a Query to do
    so in the Transaction \a t and returns the Query. If not, it returns
    0 and does nothing. It does not commit the transaction.
*/

Query * Mailbox::remove( Transaction * t )
{
    if ( synthetic() || deleted() )
        return 0;

    Query * q =
        new Query( "update mailboxes set deleted='t',owner=null "
                   "where id=$1", 0 );
    q->bind( 1, id() );
    t->enqueue( q );

    q = new Query( "delete from permissions where mailbox=$1", 0 );
    q->bind( 1, id() );
    t->enqueue( q );

    q = new Query( "delete from views where source=$1 or view=$1", 0 );
    q->bind( 1, id() );
    t->enqueue( q );

    MailboxReader * mr = new MailboxReader( name() );
    t->enqueue( mr->query );

    return q;
}


/*! Adds \a s to the list of sessions watching this mailbox. The
    Mailbox will call Session::refresh() when refreshment seems
    productive.

    Does nothing if \a s is already watching this mailbox.
*/

void Mailbox::addSession( Session * s )
{
    if ( d->source ) {
        Mailbox * sm = source();
        if ( sm && !sm->d->views )
            sm->d->views = new List<Mailbox>;
        if ( sm && !sm->d->views->find( this ) )
            sm->d->views->append( this );
    }
    if ( !d->sessions )
        d->sessions = new List<Session>;
    if ( s && !d->sessions->find( s ) ) {
        d->sessions->prepend( s );
        log( "Added session to mailbox " + name().utf8() +
             ", new count " + fn( d->sessions->count() ),
             Log::Debug );
    }
}


/*! Removes \a s from the list of sessions for this mailbox, or does
    nothing if \a s doesn't watch this mailbox.
*/

void Mailbox::removeSession( Session * s )
{
    if ( !d->sessions || !s )
        return;

    d->sessions->remove( s );
    log( "Removed session from mailbox " + name().utf8() +
         ", new count " + fn( d->sessions->count() ), Log::Debug );
    if ( d->sessions->isEmpty() ) {
        d->sessions = 0;
        d->threader = 0;
    }
}


/*! Creates a session initialiser for this mailbox and each view onto
    it.
*/

void Mailbox::notifySessions()
{
    // our own sessions
    if ( d->sessions )
        (void)new SessionInitialiser( this );
    // and all sessions on a view onto this mailbox
    List<Mailbox>::Iterator v( d->views );
    while ( v ) {
        // d->views is only added to, never pared down, so check
        if ( v->source() == this && v->d->sessions )
            (void)new SessionInitialiser( v );
        ++v;
    }
}


/*! Returns a pointer to the sessions on this mailbox. The return
    value may be a null pointer. In the event of client/network
    problems it may also include sessions that have recently become
    invalid.
*/

List<Session> * Mailbox::sessions() const
{
    return d->sessions;
}


/*! Records that the first unconsidered modseq for this mailbox is \a
    n. If this mailbox is a view, this is a fine and sensible thing to
    know: SessionInitialiser can call nextModSeq() and use the
    recorded value to consider only new/changed messages.

    For any mailboxes other than views, this function is almost meaningless.

    MailboxReader updates the nextModSeq() value in case of views.
*/

void Mailbox::setNextModSeq( int64 n )
{
    if ( n == d->nextModSeq )
        return;
    d->nextModSeq = n;
    notifySessions();
}


/*! Returns the value last specified by nextModSeq(), or 1 initially. */

int64 Mailbox::nextModSeq() const
{
    return d->nextModSeq;
}


/*! Returns true if \a s is syntactically valid as a mailbox name, and
    false if not. Empty names are invalid, ones that do not start with
    '/' are too, etc, etc.

    Notably, the root ("/") is not valid. This is a borderline case -
    for example "/" is valid as parent for creating new mailboxes, but
    not as name of a new mailbox.
*/

bool Mailbox::validName( const UString & s )
{
    if ( !s.startsWith( "/" ) )
        return false;
    if ( s.endsWith( "/" ) )
        return false;
    if ( s.contains( "//" ) )
        return false;
    return true;
}


/*! Returns a pointer to the Threader for this Mailbox. This is never
    a null pointer; if Mailbox doesn't have one it will create one.

    The Threader usually lives until you stop caring about it, but if
    removeSession() removes the last Session, it also removes the
    Threader.
*/

class Threader * Mailbox::threader() const
{
    if ( !d->threader )
        d->threader = new Threader( this );
    return d->threader;
}


/*! This extremely slow pattern matching helper checks that \a pattern
    (starting at character \a p) matches \a name (starting at
    character \a n), and returns 2 in case of match, 1 if a child of
    \a name might match, and 0 if neither is the case.

    There are only two wildcards: * matches zero or more characters. %
    matches zero or more characters, but does not match /.

    Note that this match is case sensitive. Our mailbox names are case
    insensitive, so the caller typically has to call
    UString::titlecased() on both arguments.
*/

uint Mailbox::match( const UString & pattern, uint p,
                     const UString & name, uint n )
{
    uint r = 0;
    while ( p <= pattern.length() ) {
        if ( pattern[p] == '*' || pattern[p] == '%' ) {
            bool star = false;
            while ( pattern[p] == '*' || pattern[p] == '%' ) {
                if ( pattern[p] == '*' )
                    star = true;
                p++;
            }
            uint i = n;
            if ( star )
                i = name.length();
            else
                while ( i < name.length() && name[i] != '/' )
                    i++;
            while ( i >= n && i <= name.length() ) {
                uint s = match( pattern, p, name, i );
                if ( s == 2 )
                    return 2;
                if ( s == 1 )
                    r = 1;
                i--;
            }
        }
        else if ( p == pattern.length() && n == name.length() ) {
            // ran out of pattern and name at the same time. success.
            return 2;
        }
        else if ( pattern[p] == name[n] ) {
            // nothing. proceed.
            p++;
        }
        else if ( pattern[p] == '/' && n >= name.length() ) {
            // we ran out of name and the pattern wants a child.
            return 1;
        }
        else {
            // plain old mismatch.
            return r;
        }
        n++;
    }
    return r;
}

