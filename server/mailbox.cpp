#include "mailbox.h"

#include "scope.h"
#include "event.h"
#include "query.h"
#include "string.h"
#include "eventloop.h"
#include "log.h"


class MailboxData {
public:
    MailboxData()
        : deleted( false ), synthetic( false ),
          parent( 0 ), children( 0 )
    {}

    String name;
    uint id, count, uidvalidity;
    bool deleted, synthetic;

    Mailbox *parent;
    List< Mailbox > *children;
};


static Mailbox *root = 0;


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


static Query *query;
static EventLoop *loop;


/*! This static function is responsible for building a tree of Mailboxes
    from the contents of the mailboxes table. It expects to be called by
    ::main().
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

                Mailbox *m = new Mailbox( *r->getString( "name" ) );
                m->d->id = *r->getInt( "id" );
                m->d->deleted = *r->getBoolean( "deleted" );
                m->d->uidvalidity = *r->getInt( "uidvalidity" );
                insert( m );
            }

            if ( query->failed() )
                log( Log::Disaster, "Couldn't create mailbox tree." );
            loop->stop();
        }
    };

    root = new Mailbox( "/" );
    
    Database *db = Database::handle();
    if ( !db ) {
        log( Log::Disaster, "Couldn't acquire a database handle." );
        return;
    }

    query = new Query( "select * from mailboxes", new MailboxReader );
    db->enqueue( query );
    db->execute();

    // The main event loop hasn't been started yet, so we create one for
    // our database handle, and stop it when they query is completed.
    
    loop = new EventLoop;
    loop->addConnection( db );
    loop->start();
}


static int nextComponent( const String &name, uint slash, String &s )
{
    int next = name.find( '/', slash );
    if ( next == -1 )
        next = name.length();
    s = name.mid( 0, next );
    return next+1;
}


/*! This private function inserts the Mailbox \a m into its proper place
    in our tree.
*/

void Mailbox::insert( Mailbox *m )
{
    String name = m->name();
    Mailbox *p = root;
    int slash = 1;

    do {
        String s;
        slash = nextComponent( name, slash, s );

        List< Mailbox > *children = p->children();
        if ( !children )
            children = p->d->children = new List< Mailbox >;

        List< Mailbox >::Iterator it = children->first();
        while ( it ) {
            if ( it->name() == s ) {
                p = it;
                break;
            }
            it++;
        }
        if ( !it ) {
            if ( (uint)slash > name.length() )
                p = m;
            else
                p = new Mailbox( name.mid( 0, slash-1 ) );
            children->append( p );
        }
    } while ( (uint)slash < name.length() );
}


/*! Returns a pointer to a Mailbox named \a name, or 0 if the named
    mailbox doesn't exist. If \a deleted is true, deleted mailboxes
    are included in the search. The \a name must be fully-qualified.
*/

Mailbox *Mailbox::find( const String &name, bool deleted )
{
    if ( name[0] != '/' )
        return 0;

    // Search for a Mailbox corresponding to each component of the name.

    Mailbox *m = root;
    int slash = 1;

    do {
        String s;
        slash = nextComponent( name, slash, s );

        if ( s.length() == 0 )
            break;

        List< Mailbox > *children = m->children();
        if ( !children )
            break;

        List< Mailbox >::Iterator it = children->first();
        while ( it ) {
            if ( it->name() == s ) {
                m = it;
                if ( (uint)slash > name.length() )
                    return m;
                break;
            }
            it++;
        }
        if ( !it )
            break;
    } while ( (uint)slash < name.length() );

    return 0;
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
