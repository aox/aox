#include "mailbox.h"

#include "dict.h"
#include "arena.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "string.h"
#include "stringlist.h"
#include "log.h"


class MailboxData {
public:
    MailboxData()
        : deleted( false ), parent( 0 ), children( 0 )
    {}

    String name;
    uint id, count, uidnext, uidvalidity;
    bool deleted;

    Mailbox *parent;
    List< Mailbox > *children;
};


static Mailbox *root = 0;
static Arena * arena = 0;
static Query *query = 0;


/*! \class Mailbox mailbox.h
    This class represents a node in the global mailbox hierarchy.

    Every Mailbox has a unique name() within the hierarchy. Any
    Mailbox that can contain messages has a non-zero numeric id() and
    attributes like uidvalidity() and count(). Mailboxes have a
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


/*! This static function is responsible for building a tree of
    Mailboxes from the contents of the mailboxes table. It expects to
    be called by ::main().

    All Mailbox objects are allocated on the Arena used while setup()
    is called.
*/

void Mailbox::setup()
{
    class MailboxReader : public EventHandler {
    public:
        void execute() {
            if ( !query->done() )
                return;

            while ( query->hasResults() ) {
                Row *r = query->nextRow();

                Mailbox * m = obtain( r->getString( "name" ) );
                m->d->id = r->getInt( "id" );
                m->d->deleted = r->getBoolean( "deleted" );
                m->d->uidnext = r->getInt( "uidnext" );
                m->d->uidvalidity = r->getInt( "uidvalidity" );
            }

            if ( query->failed() )
                log( Log::Disaster, "Couldn't create mailbox tree." );
        }
    };

    ::arena = Scope::current()->arena();
    ::root = new Mailbox( "/" );

    // the query and MailboxReader uses this Arena. The startup arena
    // will see a lot of activity...
    query = new Query( "select * from mailboxes", new MailboxReader );
    query->setStartUpQuery( true );
    query->execute();
}


/*! Creates a Mailbox named \a name. */

Mailbox::Mailbox( const String &name )
    : d( new MailboxData )
{
    d->name = name;
}


/*! Returns the fully qualified name of this Mailbox. */

String Mailbox::name() const
{
    return d->name;
}


/*! Returns the database ID of this Mailbox, or 0 if this Mailbox is
    synthetic(). */

uint Mailbox::id() const
{
    return d->id;
}


/*! Returns the number of messages in this Mailbox, or 0 if this
    Mailbox is deleted() or synthetic().

    Is this in RAM or in the database? Can it lag behind reality?
*/

uint Mailbox::count() const
{
    return d->count;
}


/*! Returns the next UID value that will be used for this mailbox. */

uint Mailbox::uidnext() const
{
    return d->uidnext;
}


/*! Returns the UIDVALIDITY value of this Mailbox. This never changes. */

uint Mailbox::uidvalidity() const
{
    return d->uidvalidity;
}


/*! Returns true if this mailbox is currently deleted. */

bool Mailbox::deleted() const
{
    return d->deleted;
}


/*! Returns true if this Mailbox has been synthesized in-RAM in order
    to fully connect the mailbox tree, and false if the Mailbox exists
    in the database.
*/

bool Mailbox::synthetic() const
{
    return !id();
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

List< Mailbox > *Mailbox::children() const
{
    return d->children;
}


/*! Returns a pointer to a Mailbox named \a name, or 0 if the named
    mailbox doesn't exist. If \a deleted is true, deleted mailboxes
    are included in the search. The \a name must be fully-qualified.
*/

Mailbox *Mailbox::find( const String &name, bool deleted )
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


/*! Obtain a mailbox with \a name, creating Mailbox objects as
    necessary and permitted.

    if \a create is true (this is the default) and there is no such Mailbox,
    obtain() creates one, including parents, etc.

    If \a create is false and there is no such Mailbox, obtain()
    returns null without creating anything.
*/

Mailbox * Mailbox::obtain( const String & name, bool create )
{
    if ( name[0] != '/' )
        return 0;

    uint i = name.length();
    while ( i > 0 && name[i] != '/' )
        i--;
    Mailbox * parent = root;
    if ( i > 0 )
        parent = obtain( name.mid( 0, i ), create );
    if ( !parent )
        return 0;

    List<Mailbox>::Iterator it( parent->children()->first() );
    while ( it ) {
        if ( it->name() == name )
            return it;
        ++it;
    }
    if ( !create )
        return 0;

    Scope x( ::arena );
    Mailbox * m = new Mailbox( name );
    parent->d->children->append( m );
    return m;
}


/*! Changes this Mailbox's uidnext value to \a n. No checks are
    performed - although uidnext should monotonically increase, this
    function gives you total liberty.

    Only OCClient is meant to call this function. Calling it elsewhere
    will likely disturb either OCClient, ocd, ImapSession or Arnt.
*/

void Mailbox::setUidnext( uint n )
{
    d->uidnext = n;
}


/*! Changes this Mailbox's deletedness to \a del.

    Only OCClient is meant to call this function -- see setUidnext().
*/

void Mailbox::setDeleted( bool del )
{
    d->deleted = del;
}
