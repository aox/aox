#include "mailbox.h"

#include "dict.h"
#include "scope.h"
#include "event.h"
#include "query.h"
#include "string.h"
#include "stringlist.h"
#include "eventloop.h"
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

            // We'll compose an ocd-like message for each Mailbox, and
            // use update() to build the in-memory tree representation
            // of the mailboxes table.

            while ( query->hasResults() ) {
                Row *r = query->nextRow();

                String m = r->getString( "name" );
                StringList data;

                String id = fn( r->getInt( "id" ) );
                data.append( "id=" + id );

                String deleted = "f";
                if ( r->getBoolean( "deleted" ) )
                    deleted = "t";
                data.append( "deleted=" + deleted );

                String uidnext = fn( r->getInt( "uidnext" ) );
                data.append( "uidnext=" + uidnext );

                String uidvalidity = fn( r->getInt( "uidvalidity" ) );
                data.append( "uidvalidity=" + uidvalidity );

                m.append( ' ' );
                m.append( data.join( "," ) );

                update( m );
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


static int nextComponent( const String &name, uint slash, String &s )
{
    int next = name.find( '/', slash );
    if ( next == -1 )
        next = name.length();
    s = name.mid( 0, next );
    return next+1;
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


/*! This function uses the string \a s to update the Mailbox tree.
    (This description is inadequate. Will be fixed when the picture
    clears sufficiently.)
*/

void Mailbox::update( const String &s )
{
    int i = s.find( ' ' );
    String name = s.mid( 0, i );
    Dict< String > data;

    int last = i+1;
    do {
        i = s.find( ',', last );

        String datum;
        if ( i > 0 ) {
            datum = s.mid( last, i-last );
            last = i+1;
        }
        else {
            datum = s.mid( last );
        }

        int eq = datum.find( '=' );
        data.insert( datum.mid( 0, eq ),
                     new String( datum.mid( eq+1 ) ) );
    } while ( i > 0 );

    Mailbox *m = root;
    int slash = 1;

    do {
        String s;
        slash = nextComponent( name, slash, s );

        List< Mailbox > *children = m->children();
        if ( !children )
            children = m->d->children = new List< Mailbox >;

        List< Mailbox >::Iterator it = children->first();
        while ( it ) {
            if ( it->name() == s ) {
                m = it;
                break;
            }
            it++;
        }
        if ( !it ) {
            if ( (uint)slash > name.length() )
                m = new Mailbox( name );
            else
                m = new Mailbox( name.mid( 0, slash-1 ) );
            children->append( m );
        }
    } while ( (uint)slash < name.length() );

    if ( data.contains( "id" ) ) {
        uint id = data.find( "id" )->number( 0 );
        m->d->id = id;
    }

    if ( data.contains( "deleted" ) ) {
        String deleted = *data.find( "deleted" );

        if ( deleted == "t" )
            m->d->deleted = true;
        else
            m->d->deleted = false;
    }

    if ( data.contains( "uidnext" ) ) {
        uint uidnext = data.find( "uidnext" )->number( 0 );
        m->d->uidnext = uidnext;
    }

    if ( data.contains( "uidvalidity" ) ) {
        uint uidvalidity = data.find( "uidvalidity" )->number( 0 );
        m->d->uidvalidity = uidvalidity;
    }
}
