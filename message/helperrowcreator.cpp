// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "helperrowcreator.h"

#include "dict.h"
#include "scope.h"
#include "allocator.h"
#include "transaction.h"
#include "address.h"
#include "query.h"
#include "flag.h"
#include "utf.h"



/*! \class HelperRowCreator helperrowcreator.h

    The HelperRowCreator class contains common logic and some code to
    add rows to the helper tables flag_names, annotation_names and
    header_fields. It's inherited by one class per table.

    In theory this could handle bodyparts and addresses, but I think
    not. Those are different. Those tables grow to be big. These three
    tables frequently contain less than one row per thousand messages,
    so we need to optimise this class for inserting zero, one or at
    most a few rows.
*/


class HelperRowCreatorData
    : public Garbage
{
public:
    HelperRowCreatorData()
        : s( 0 ), c( 0 ), notify( 0 ), parent( 0 ), t( 0 ),
          done( false ), inserted( false )
    {}

    Query * s;
    Query * c;
    Query * notify;
    Transaction * parent;
    Transaction * t;
    EString n;
    EString e;
    bool done;
    bool inserted;
    Dict<uint> names;
};


/*!  Constructs an empty HelperRowCreator refering to \a table, using
     \a transaction. If an error related to \a constraint occurs,
     execute() will roll back to a savepoint and try again.
*/

HelperRowCreator::HelperRowCreator( const EString & table,
                                    Transaction * transaction,
                                    const EString & constraint )
    : EventHandler(), d( new HelperRowCreatorData )
{
    setLog( new Log );
    d->parent = transaction;
    d->n = table + "_creator";
    d->e = constraint;
}


/*! Returns true if this object is done with the Transaction, and
    false if it will use the Transaction for one or more queries.
*/

bool HelperRowCreator::done() const
{
    return d->done;
}


void HelperRowCreator::execute()
{
    Scope x( log() );
    while ( !d->done ) {
        // If we're waiting for the db, just go away.
        if ( d->s && !d->s->done() )
            return;
        if ( d->c && !d->c->done() )
            return;

        // First, we select the rows whose IDs we need.
        if ( !d->s && !d->c ) {
            d->s = makeSelect();
            if ( d->s ) {
                // We don't know all we need, so issue a select.
                if ( !d->t )
                    d->t = d->parent->subTransaction( this );
                d->t->enqueue( d->s );
                d->t->execute();
            }
            else {
                // We do know everything, so we're done.
                d->done = true;
            }
        }

        // When the select is done, see if we need to copy into the table.
        if ( d->s && d->s->done() && !d->c ) {
            processSelect( d->s );
            d->s = 0;
            d->c = makeCopy();
            if ( d->c ) {
                // We do need to insert something.
                d->t->enqueue( d->c );
                EString ed = d->n;
                ed.replace( "creator", "extended" );
                Query * q = new Query( "notify " + ed, this );
                d->t->enqueue( q );
                d->t->execute();
                d->inserted = true;
            }
        }

        // If we need to insert something, look at the fate of the copy.
        if ( d->c && d->c->done() ) {
            Query * c = d->c;
            d->c = 0;
            if ( !c->failed() ) {
                // We inserted, hit no race, and want to run another
                // select to find the IDs.
            }
            else if ( c->error().contains( d->e ) ) {
                // We inserted, but there was a race and we lost it.
                d->t->restart();
            }
            else {
                // Total failure. The Transaction is now in Failed
                // state, and there's nothing we can do other. We just
                // have to let our owner deal with it.
                d->done = true;
            }
        }
    }

    if ( !d->t )
        return;

    Transaction * t = d->t;
    d->t = 0;
    t->commit();
}


/*! \fn Query * HelperRowCreator::makeSelect()

    This pure virtual function is called to make a query to return the
    IDs of rows already in the database, or of newly inserted rows.

    If nothing needs to be done, the makeSelect() can return a null
    pointer.

    If makeSelect() returns non-null, the returned Query should have
    this object as owner.
 */


/*! This virtual function is called to process the result of the
    makeSelect() Query. \a q is the Query returned by makeSelect()
    (never 0).
 */

void HelperRowCreator::processSelect( Query * q )
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        add( r->getEString( "name" ), r->getInt( "id" ) );
    }
}


/*! \fn Query * HelperRowCreator::makeCopy()

    This pure virtual function is called to make a query to insert the
    necessary rows to the table.

    If nothing needs to be inserted, makeCopy() can return 0.

    If makeCopy() returns non-null, the returned Query should have
    this object as owner.
 */


/*! Remembers that the given name \a s corresponds to the \a id. */

void HelperRowCreator::add( const EString & s, uint id )
{
    uint * tmp = (uint *)Allocator::alloc( sizeof(uint), 0 );
    *tmp = id;

    d->names.insert( s.lower(), tmp );
}


/*! Returns the id stored earlier with add() for the name \a s. */

uint HelperRowCreator::id( const EString & s )
{
    uint * p = d->names.find( s.lower() );
    if ( p )
        return *p;
    return 0;
}


/*! Returns true if this creator inserted at least one row, and false
    if lookup alone was enough to do the work.
*/

bool HelperRowCreator::inserted() const
{
    return d->inserted;
}


/*! \class FlagCreator helperrowcreator.h

    This class issuses queries using a supplied Transaction to add new
    flags to the database.
*/


/*! Starts constructing the queries needed to create the flags specified
    in \a f within the transaction \a t. This object will notify the
    Transaction::owner() when it's done.

    \a t will fail if flag creation fails for some reason (typically
    bugs). Transaction::error() should say what went wrong.
*/

FlagCreator::FlagCreator( const EStringList & f, Transaction * t )
    : HelperRowCreator( "flag_names", t, "fn_uname" ),
      names( f )
{
}


Query * FlagCreator::makeSelect()
{
    Query * s = new Query( "select id, name from flag_names where "
                           "lower(name)=any($1::text[])", this );

    EStringList sl;
    EStringList::Iterator it( names );
    while ( it ) {
        EString name( *it );
        if ( id( name ) == 0 && Flag::id( name ) == 0 )
            sl.append( name.lower() );
        ++it;
    }

    if ( sl.isEmpty() )
        return 0;
    s->bind( 1, sl );
    log( "Looking up " + fn( sl.count() ) + " flags", Log::Debug );
    return s;
}


Query * FlagCreator::makeCopy()
{
    Query * c = new Query( "copy flag_names (name) from stdin with binary",
                           this );
    uint count = 0;
    EStringList::Iterator it( names );
    while ( it ) {
        if ( id( *it ) == 0 && Flag::id( *it ) == 0 ) {
            c->bind( 1, *it );
            c->submitLine();
            count++;
        }
        ++it;
    }

    if ( !count )
        return 0;
    log( "Inserting " + fn( count ) + " new flags" );
    return c;

}


/*! \fn EStringList * FlagCreator::allFlags()

    Returns a pointer to a list of all flags known to this FlagCreator.
*/


/*! \class FieldNameCreator helperrowcreator.h

    The FieldNameCreator is a HelperRowCreator to insert rows into the
    field_names table. Nothing particular.
*/


/*! Creates an object to ensure that all entries in \a f are present
    in field_names, using \a tr for all its queryies.
*/


FieldNameCreator::FieldNameCreator( const EStringList & f,
                                    Transaction * tr )
    : HelperRowCreator( "field_names", tr,  "field_names_name_key" ),
      names( f )
{
}


Query * FieldNameCreator::makeSelect()
{
    Query * q = new Query( "select id, name from field_names where "
                           "name=any($1::text[])", this );

    EStringList sl;
    EStringList::Iterator it( names );
    while ( it ) {
        if ( !id( *it ) )
            sl.append( *it );
        ++it;
    }
    if ( sl.isEmpty() )
        return 0;
    q->bind( 1, sl );
    log( "Looking up " + fn( sl.count() ) + " field names", Log::Debug );
    return q;
}


Query * FieldNameCreator::makeCopy()
{
    Query * q = new Query( "copy field_names (name) from stdin with binary",
                           this );
    EStringList::Iterator it( names );
    uint count = 0;
    while ( it ) {
        if ( !id( *it ) ) {
            q->bind( 1, *it );
            q->submitLine();
            count++;
        }
        ++it;
    }

    if ( !count )
        return 0;
    log( "Inserting " + fn( count ) + " new header field names" );
    return q;
}


/*! \class AnnotationNameCreator helperrowcreator.h

    The AnnotationNameCreator is a HelperRowCreator to insert rows into
    the annotation_names table. Nothing particular.
*/


/*! Creates an object to ensure that all entries in \a f are present
    in annotation_names, using \a t for all its queryies.
*/

AnnotationNameCreator::AnnotationNameCreator( const EStringList & f,
                                              Transaction * t )
    : HelperRowCreator( "annotation_names", t, "annotation_names_name_key" ),
      names( f )
{
}

Query *  AnnotationNameCreator::makeSelect()
{
    Query * q = new Query( "select id, name from annotation_names where "
                           "name=any($1::text[])", this );

    EStringList sl;
    EStringList::Iterator it( names );
    while ( it ) {
        EString name( *it );
        if ( id( name ) == 0 )
            sl.append( name );
        ++it;
    }
    if ( sl.isEmpty() )
        return 0;

    q->bind( 1, sl );
    log( "Looking up " + fn( sl.count() ) + " annotation names", Log::Debug );
    return q;
}


Query * AnnotationNameCreator::makeCopy()
{
    Query * q = new Query( "copy annotation_names (name) "
                           "from stdin with binary", this );
    EStringList::Iterator it( names );
    uint count = 0;
    while ( it ) {
        if ( id( *it ) == 0 ) {
            count++;
            q->bind( 1, *it );
            q->submitLine();
        }
        ++it;
    }

    if ( !count )
        return 0;
    log( "Inserting " + fn( count ) + " new annotation names" );
    return q;
}


/*! \class AddressCreator helperrowcreator.h

    The AddressCreator ensures that a set of addresses exist in the
    database and that their addresses are known.

    You have to create an object, then execute it. It'll use a
    subtransaction and implicitly block your transaction until the IDs
    are known.
*/


/*! Constructs an AddressCreator which will ensure that all the \a
    addresses have an Address::id(), using a subtransaction if \a t
    for its work.
*/

AddressCreator::AddressCreator( Dict<Address> * addresses,
                                Transaction * t )
    : HelperRowCreator( "addresses", t, "addresses_nld_key" ),
      a( addresses ), bulk( false ), decided( false ),
      base( t ), sub( 0 ), insert( 0 ), obtain( 0 )
{
}


/*! Constructs an AddressCreator which will ensure that \a address has
    an Address::id(), using a subtransaction if \a t for its work.
*/

AddressCreator::AddressCreator( Address * address, class Transaction * t )
    : HelperRowCreator( "addresses", t, "addresses_nld_key" ),
      a( new Dict<Address> ), bulk( false ), decided( false ),
      base( t ), sub( 0 ), insert( 0 ), obtain( 0 )
{
    a->insert( AddressCreator::key( address ), address );
}


/*! Constructs an AddressCreator which will ensure that all the \a
    addresses have an Address::id(), using a subtransaction if \a t
    for its work.
*/


AddressCreator::AddressCreator( List<Address> * addresses,
                                class Transaction * t )
    : HelperRowCreator( "addresses", t, "addresses_nld_key" ),
      a( new Dict<Address> ), bulk( false ), decided( false ),
      base( t ), sub( 0 ), insert( 0 ), obtain( 0 )
{
    List<Address>::Iterator address( addresses );
    while ( address ) {
        a->insert( AddressCreator::key( address ), address );
        ++address;
    }
}


/*! This private helper looks for \a s in \a b, inserts it if not
    present, and returns its number. Uses \a n to generate a new
    unique number if necessary, and binds \a s to \a n in \a q.

    \a b has to use key() as key for each member. Nothing will work if
    you break this rule. This sounds a little fragile, but I can't
    think of a good alternative right now.
*/

uint AddressCreator::param( Dict<uint> * b, const EString & s,
                            uint & n,
                            Query * q )
{
    uint * r = b->find( s );
    if ( !r ) {
        r = (uint*)Allocator::alloc( sizeof( uint ), 0 );
        *r = n++;
        b->insert( s, r );
        q->bind( *r, s );
    }
    return *r;
}


/*! Creates a select to look for as many addresses as possible, but
    binding no more than 128 strings.
*/

Query * AddressCreator::makeSelect()
{
    EString s = "select id, name, localpart, domain from addresses where ";
    Query * q = new Query( "", this );
    uint n = 1;
    Dict<uint> binds;
    PgUtf8Codec p;
    bool first = true;
    Dict<Address>::Iterator i( a );
    asked.clear();
    while ( i && n < 128 ) {
        if ( !i->id() ) {
            EString name( p.fromUnicode( i->uname() ) );
            EString lp( i->localpart() );
            EString dom( i->domain().lower() );

            uint bn = param( &binds, name, n, q );
            uint bl = param( &binds, lp, n, q );
            uint bd = param( &binds, dom, n, q );

            if ( !first )
                s.append( " or " );
            first = false;
            s.append( "(name=$" );
            s.appendNumber( bn );
            s.append( " and localpart=$" );
            s.appendNumber( bl );
            s.append( " and lower(domain)=$" );
            s.appendNumber( bd );
            s.append( ")" );

            asked.append( i );
        }
        ++i;
    }
    if ( asked.isEmpty() )
        return 0;
    q->setString( s );
    log( "Looking up " + fn( asked.count() ) + " addresses", Log::Debug );
    return q;
}


void AddressCreator::processSelect( Query * q )
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        Address * c =
            new Address( r->getUString( "name" ),
                         r->getEString( "localpart" ),
                         r->getEString( "domain" ) );
        Address * our = a->find( key( c ) );
        if ( our )
            our->setId( r->getInt( "id" ) );
        else
            log( "Unexpected result from db: " + c->toString() );
    }
}


Query * AddressCreator::makeCopy()
{
    uint count = 0;
    Query * q = new Query( "copy addresses (name,localpart,domain) "
                           "from stdin with binary", this );
    List<Address>::Iterator i( asked );
    while ( i ) {
        if ( !i->id() ) {
            q->bind( 1, i->uname() );
            q->bind( 2, i->localpart() );
            q->bind( 3, i->domain() );
            q->submitLine();
            count++;
        }
        ++i;
    }
    if ( !count )
        return 0;
    log( "Inserting " + fn( count ) + " new addresses" );
    return q;
}


/*! Returns a EString derived from \a a in a unique fashion. Two
    addresses that are the same according to the RFC rules have the
    same key().
*/

EString AddressCreator::key( Address * a )
{
    EString r;
    r.append( a->domain().lower() );
    r.append( '\0' );
    r.append( a->localpart() );
    r.append( '\0' );
    r.append( a->uname().utf8() );
    return r;
}


// this constant decides when we change to using the temptable. where's
// the crossover point?

static uint useTempTable = 30;


/*! This overloads HelperRowCreator::execute() and conditionally
    replaces its state machine with one that's faster for large
    address sets.
*/

void AddressCreator::execute()
{
    Scope x( log() );
    if ( !decided ) {
        uint c = 0;
        Dict<Address>::Iterator i( a );
        while ( c < useTempTable && i ) {
            if ( !i->id() )
                ++c;
            ++i;
        }
        if ( c >= useTempTable )
            bulk = true;
        decided = true;
    }

    if ( !bulk ) {
        HelperRowCreator::execute();
        return;
    }

    if ( !sub ) {
        base->enqueue( new Query( "create temporary table na ("
                                  "id integer, "
                                  "f boolean, "
                                  "name text, "
                                  "localpart text, "
                                  "domain text )", 0 ) );
        Query * q = new Query( "copy na (id, f, name,localpart,domain) "
                               "from stdin with binary", this );
        Dict<Address>::Iterator i( a );
        while ( i ) {
            if ( !i->id() ) {
                q->bind( 1, 0 );
                q->bind( 2, false );
                q->bind( 3, i->uname() );
                q->bind( 4, i->localpart() );
                q->bind( 5, i->domain() );
                q->submitLine();
            }
            ++i;
        }
        base->enqueue( q );

        sub = base->subTransaction( this );
    }

    if ( insert && insert->failed() ) {
        sub->restart();
        insert = 0;
    }

    if ( !insert ) {
        sub->enqueue(
            new Query(
                "update na set f=true, id=a.id from addresses a "
                "where na.localpart=a.localpart "
                "and lower(na.domain)=lower(a.domain) "
                "and na.name=a.name "
                "and not f", 0 ) );
        sub->enqueue(
            new Query(
                "update na "
                "set id=nextval(pg_get_serial_sequence('addresses','id')) "
                "where id = 0 and not f", 0 ) );
        insert =
            new Query(
                "insert into addresses "
                "(id, name, localpart, domain) "
                "select id, name, localpart, domain "
                "from na where not f", this );
        sub->enqueue( insert );
        sub->execute();
    }

    if ( !insert->done() )
        return;

    if ( !obtain ) {
        obtain = new Query( "select id, name, localpart, domain "
                            "from na", this );
        sub->enqueue( obtain );
        sub->enqueue( new Query( "drop table na", 0 ) );
        sub->commit();
    }

    processSelect( obtain );
}


/*! \class ThreadRootCreator helperrowcreator.h

    The ThreadRootCreator class thread_roots rows. The only particular
    here is that id() works on all the message-ids, not just the root
    ids.
*/

/*! Constructs a ThreadRootCreator that will make sure that the
    messages in \a l are all threadable, using a subtransaction of \a
    t for all db work.
*/

ThreadRootCreator::ThreadRootCreator( List<ThreadRootCreator::Message> * l,
                                      Transaction * t )
    : HelperRowCreator( "thread_roots", t, "thread_roots_messageid_key" ),
      messages( l ), nodes( new Dict<ThreadNode> ), first( true )
{
    List<Message>::Iterator m( messages );
    while ( m ) {
        EStringList l = m->references();
        l.append( m->messageId() );
        ++m;
        EStringList::Iterator s( l );
        ThreadNode * parent = 0;
        while ( s ) {
            if ( !s->isEmpty() ) {
                ThreadNode * n = nodes->find( *s );
                if ( !n ) {
                    n = new ThreadNode( *s );
                    nodes->insert( *s, n );
                }
                if ( parent ) {
                    // if we have a parent, and the parent is a child
                    // of the supposed child, then
                    ThreadNode * p = parent;
                    while ( p && p != n )
                        p = p->parent;
                    if ( p == n )
                        parent = 0; // then don't use that parent
                }
                if ( n == parent ) {
                    // evil case. let's not do anything
                }
                else if ( parent && n->parent == parent ) {
                    // nice case, hopefully common. no need to act.
                }
                else if ( parent && n->parent ) {
                    // the DAG disagrees with the references chain
                    // we're processing. go up to both roots, and
                    // merge them if they differ.
                    ThreadNode * p = parent;
                    while ( p->parent )
                        p = p->parent;
                    ThreadNode * f = n;
                    while ( f->parent )
                        f = f->parent;
                    if ( p != f )
                        p->parent = f;
                }
                else if ( parent ) {
                    // we didn't know about a parent for this
                    // message-id, now we do. record it.
                    n->parent = parent;
                }
                parent = n;
            }
            ++s;
        };
    }
}


Query * ThreadRootCreator::makeSelect()
{
    Query * q = 0;
    EStringList l;
    Dict<ThreadNode>::Iterator i( nodes );
    if ( first ) {
        // the first time around we might find IDs
        while ( i ) {
            ThreadNode * n = i;
            ThreadNode * p = n;
            while ( p->parent )
                p = p->parent;
            if ( !p->trid )
                l.append( n->id );
            ++i;
        }
        q = new Query( "select id, messageid as name from thread_roots "
                       "where messageid=any($1::text[]) "
                       "union "
                       "select m.thread_root as id, hf.value as name "
                       "from messages m join header_fields hf on "
                       "(m.id=hf.message and hf.field=13) "
                       "where hf.value=any($1::text[]) "
                       "and m.thread_root is not null",
                       this );
        first = false;
    }
    else {
        while ( i ) {
            if ( !i->parent && !i->trid )
                l.append( i->id );
            ++i;
        }
        q = new Query( "select id, messageid as name from thread_roots "
                       "where messageid=any($1::text[])",
                       this );
    }
    if ( l.isEmpty() )
        return 0;
    q->bind( 1, l );
    return q;
}


Query * ThreadRootCreator::makeCopy()
{
    Query * q = new Query( "copy thread_roots( messageid ) "
                           "from stdin with binary", 0 );
    Dict<ThreadNode>::Iterator i( nodes );
    while ( i ) {
        if ( !i->parent && !i->trid ) {
            q->bind( 1, i->id );
            q->submitLine();
        }
        ++i;
    }
    return q;
}


uint ThreadRootCreator::id( const EString & id )
{
    ThreadNode * n = nodes->find( id );
    if ( !n )
        return HelperRowCreator::id( id );
    while ( n->parent )
        n = n->parent;
    return n->trid;
}


void ThreadRootCreator::add( const EString & id, uint i )
{
    ThreadNode * n = nodes->find( id );
    if ( !n ) {
        n = new ThreadNode( id );
        nodes->insert( id, n );
    }
    while ( n->parent ) {
        if ( n->trid && n->trid != i ) {
            uint old = n->trid;
            if ( !merged.contains( old ) ) {
                Dict<ThreadNode>::Iterator o( nodes );
                while ( o ) {
                    if ( o->trid == old )
                        o->trid = i;
                    ++o;
                }
                ThreadRootCreator::Message * hack = messages->first();
                if ( hack )
                    hack->mergeThreads( i, old );
                merged.add( old );
            }
        }
        n = n->parent;
    }
    n->trid = i;
    HelperRowCreator::add( n->id, i );
}
