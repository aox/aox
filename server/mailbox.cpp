// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mailbox.h"

#include "log.h"
#include "map.h"
#include "dict.h"
#include "user.h"
#include "query.h"
#include "scope.h"
#include "event.h"
#include "timer.h"
#include "string.h"
#include "message.h"
#include "fetcher.h"
#include "session.h"
#include "dbsignal.h"
#include "threader.h"
#include "eventloop.h"
#include "allocator.h"
#include "messageset.h"
#include "stringlist.h"
#include "transaction.h"


static Map<Mailbox> * mailboxes = 0;
static UDict<Mailbox> * mailboxesByName = 0;
static bool wiped = false;


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
    Query * q;
    bool done;

    MailboxReader( EventHandler * ev, int64 );
    void execute();
};


static List<MailboxReader> * readers = 0;


MailboxReader::MailboxReader( EventHandler * ev, int64 c )
    : owner( ev ), q( 0 ), done( false )
{
    if ( !::readers ) {
        ::readers = new List<MailboxReader>;
        Allocator::addEternal( ::readers, "active mailbox readers" );
    }
    ::readers->append( this );
    q = new Query( "select m.id, m.name, m.deleted, m.owner, "
                   "m.uidnext, m.nextmodseq, m.uidvalidity, "
                   "v.nextmodseq as viewnms, v.selector, "
                   "v.view, v.source "
                   //"m.change " // better: m.change
                   "from mailboxes m "
                   "left join views v on (m.id=v.view) ",
                   //"where change>=$1"
                   this );
    c = c; //query->bind( 1, c );
}


void MailboxReader::execute() {
    while ( q->hasResults() ) {
        Row * r = q->nextRow();

        UString n = r->getUString( "name" );
        uint id = r->getInt( "id" );
        Mailbox * m = ::mailboxes->find( id );
        if ( !m || m->name() != n ) {
            m = Mailbox::obtain( n );
            if ( n != m->d->name )
                m->d->name = n;
            m->setId( id );
            ::mailboxes->insert( id, m );
        }

        if ( r->getBoolean( "deleted" ) )
            m->setType( Mailbox::Deleted );
        else if ( r->isNull( "view" ) )
            m->setType( Mailbox::Ordinary );
        else
            m->setType( Mailbox::View );

        m->d->uidvalidity = r->getInt( "uidvalidity" );
        if ( !r->isNull( "owner" ) )
            m->setOwner( r->getInt( "owner" ) );

        if ( m->type() == Mailbox::View ) {
            m->d->source = r->getInt( "source" );
            m->d->selector = r->getString( "selector" );
            m->setUidnextAndNextModSeq( r->getInt( "uidnext" ),
                                        r->getBigint( "viewnms" ),
                                        q->transaction() );
        }
        else {
            m->setUidnextAndNextModSeq( r->getInt( "uidnext" ),
                                        r->getBigint( "nextmodseq" ),
                                        q->transaction() );
        }
    }

    if ( !q->done() || done )
        return;

    done = true;
    ::readers->remove( this );
    ::wiped = false;
    if ( q->failed() && !EventLoop::global()->inShutdown() )
        log( "Couldn't create mailbox tree: " + q->error(), Log::Disaster );
    if ( owner )
        owner->execute();
    if ( q->transaction() )
        q->transaction()->commit();
};


class MailboxesWatcher
    : public EventHandler
{
public:
    MailboxesWatcher(): EventHandler(), t( 0 ), m( 0 ) {
        (void)new DatabaseSignal( "mailboxes_updated", this );
    }
    void execute() {
        if ( EventLoop::global()->inShutdown() )
            return;

        if ( !t ) {
            // use a timer to run only one mailboxreader per 2-3
            // seconds.
            t = new Timer( this, 2 );
        }
        else if ( t->active() ) {
            // the timer is already running, so ignore this
        }
        else if ( m && !m->done ) {
            // a mailboxreader is working, and one is enough, so try
            // again later
            t = new Timer( this, 2 );
        }
        else {
            // time's out, time to work
            t = 0;
            m = new MailboxReader( 0, 0 );
            m->q->execute();
        }
    }
    Timer * t;
    MailboxReader * m;
};


// this helper class is used to recover when Oryx testing tools
// violate various database invariants.
class MailboxObliterator
    : public EventHandler
{
public:
    MailboxReader * mr;
    MailboxObliterator(): EventHandler(), mr( 0 ) {
        setLog( new Log( Log::Server ) );
        (void)new DatabaseSignal( "obliterated", this );
    }
    void execute() {
        if ( !mr ) {
            ::mailboxes->clear();
            ::mailboxesByName->clear();
            ::wiped = true;
            (void)Mailbox::root();
            mr = new MailboxReader( this, 0 );
            mr->q->execute();
        }

        if ( !mr->done )
            return;

        mr = 0;
    }
};


/*! This static function is responsible for building a tree of
    Mailboxes from the contents of the mailboxes table. It expects to
    be called by ::main().

    The \a owner (if one is specified) is notified of completion.
*/

void Mailbox::setup( EventHandler * owner )
{
    ::wiped = true;

    ::mailboxes = new Map<Mailbox>;
    Allocator::addEternal( ::mailboxes, "mailbox tree" );

    ::mailboxesByName = new UDict<Mailbox>;
    Allocator::addEternal( ::mailboxesByName, "mailbox tree" );

    (void)root();

    (new MailboxReader( owner, 0 ))->q->execute();

    (void)new MailboxesWatcher;
    if ( !Configuration::toggle( Configuration::Security ) )
        (void)new MailboxObliterator;
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
    if ( !d->parent )
        return true;
    if ( d->owner == d->parent->d->owner )
        return false;
    return true;
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

Mailbox * Mailbox::root()
{
    UString r;
    r.append( '/' );
    return Mailbox::obtain( r, true );
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
*/

Mailbox * Mailbox::closestParent( const UString & name )
{
    if ( name[0] != '/' )
        return 0;

    UString n = name.titlecased();
    Mailbox * m = find( n );
    while ( !m || ( m->synthetic() && !m->isHome() ) ) {
        uint i = n.length() - 1;
        while ( i > 0 && n[i] != '/' )
            i--;
        n.truncate( i );
        m = find( n );
    }
    return m;
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

    UString n = name.titlecased();
    Mailbox * m = ::mailboxesByName->find( n );
    if ( m || !create )
        return m;
    uint i = 0;
    Mailbox * p = 0;
    while ( i <= n.length() ) {
        if ( i >= n.length() || n[i] == '/' ) {
            uint l = i;
            if ( !l )
                l = 1;
            m = ::mailboxesByName->find( n.mid( 0, l ) );
            if ( !m ) {
                m = new Mailbox( name.mid( 0, l ) );
                ::mailboxesByName->insert( n.mid( 0, l ), m );
                if ( p ) {
                    if ( !p->d->children )
                        p->d->children = new List<Mailbox>;
                    p->d->children->append( m );
                    m->d->parent = p;
                }
            }
            p = m;
        }
        i++;
    }
    return m;
}


/*! Sets this Mailbox's owner to \a n (which is assumed to be a valid
    user id).
*/

void Mailbox::setOwner( uint n )
{
    d->owner = n;
}


/*! Atomically sets both uidnext() to \a n and nextModSeq() to \a
    m. Uses subtransactions of \a t for all work needed.
*/

void Mailbox::setUidnextAndNextModSeq( uint n, int64 m, Transaction * t )
{
    if ( n == d->uidnext && m == d->nextModSeq )
        return;
    d->uidnext = n;
    d->nextModSeq = m;

    if ( d->sessions )
        (void)new SessionInitialiser( this, t );

    List<Mailbox>::Iterator v( d->views );
    while ( v ) {
        // d->views is only added to, never pared down, so check
        if ( v->source() == this && v->d->sessions ) {
            v->d->nextModSeq = n; // is this line right? not sure.
            (void)new SessionInitialiser( v, t );
        }

        ++v;
    }
}


/*! Changes this Mailbox's deletedness to \a del. */

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

    t->enqueue( new Query( "notify mailboxes_updated", 0 ) );

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

    t->enqueue( new Query( "notify mailboxes_updated", 0 ) );

    return q;
}


/*! Adds one or more queries to \a t, to ensure that the Mailbox tree
    is up to date when \a t is commited.
*/

void Mailbox::refreshMailboxes( class Transaction * t )
{
    Transaction * s = t->subTransaction();
    s->enqueue( (new MailboxReader( 0, 0 ))->q );
    s->execute();
    t->enqueue( new Query( "notify mailboxes_updated", 0 ) );
}


/*! Adds \a s to the list of sessions watching this mailbox. The
    SessionInitialiser will update \a s when necessary.

    Does nothing if \a s is already watching this mailbox.
*/

void Mailbox::addSession( Session * s )
{
    if ( d->source ) {
        Mailbox * sm = source();
        if ( sm && sm->d->nextModSeq > d->nextModSeq )
            d->nextModSeq = sm->d->nextModSeq;
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


/*! Returns a pointer to the sessions on this mailbox. The return
    value may be a null pointer. In the event of client/network
    problems it may also include sessions that have recently become
    invalid.
*/

List<Session> * Mailbox::sessions() const
{
    return d->sessions;
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
                if ( s == 1 || star )
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


/*! Returns true if the Mailbox subsystem is currently in the process
    of relearning all the Mailbox objects from the database. Never
    returns true during normal operations, but may if if the database
    is wiped out by a test rig.
*/

bool Mailbox::refreshing()
{
    if ( !::wiped )
        return false;
    if ( !::readers )
        return false;
    if ( ::readers->isEmpty() )
        return false;
    return true;
}
