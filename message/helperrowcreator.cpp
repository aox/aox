// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "helperrowcreator.h"

#include "dict.h"
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
          done( false )
    {}

    Query * s;
    Query * c;
    Query * notify;
    Transaction * parent;
    Transaction * t;
    EString n;
    EString e;
    bool done;
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
    // the parent transaction's owner may have to wait for this creator
    // to finish.  notify it just in case.
    if ( t->parent() )
        t->parent()->notify();
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
    return s;
}


Query * FlagCreator::makeCopy()
{
    Query * c = new Query( "copy flag_names (name) from stdin with binary",
                           this );
    bool any = false;
    EStringList::Iterator it( names );
    while ( it ) {
        if ( id( *it ) == 0 && Flag::id( *it ) == 0 ) {
            c->bind( 1, *it );
            c->submitLine();
            any = true;
        }
        ++it;
    }

    if ( !any )
        return 0;
    return c;

}


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
    return q;
}


Query * FieldNameCreator::makeCopy()
{
    Query * q = new Query( "copy field_names (name) from stdin with binary",
                           this );
    EStringList::Iterator it( names );
    bool any = false;
    while ( it ) {
        if ( !id( *it ) ) {
            q->bind( 1, *it );
            q->submitLine();
            any = true;
        }
        ++it;
    }

    if ( !any )
        return 0;
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
    return q;
}


Query * AnnotationNameCreator::makeCopy()
{
    Query * q = new Query( "copy annotation_names (name) "
                           "from stdin with binary", this );
    EStringList::Iterator it( names );
    bool any = false;
    while ( it ) {
        if ( id( *it ) == 0 ) {
            any = true;
            q->bind( 1, *it );
            q->submitLine();
        }
        ++it;
    }

    if ( !any )
        return 0;
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
      a( addresses )
{
}


/*! Constructs an AddressCreator which will ensure that \a address has
    an Address::id(), using a subtransaction if \a t for its work.
*/

AddressCreator::AddressCreator( Address * address, class Transaction * t )
    : HelperRowCreator( "addresses", t, "addresses_nld_key" ),
      a( new Dict<Address> )
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
      a( new Dict<Address> )
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
    bool any = 0;
    while ( i && n < 128 ) {
        if ( !i->id() ) {
            any = true;
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
    if ( !any )
        return 0;
    q->setString( s );
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
    bool any = false;
    Query * q = new Query( "copy addresses (name,localpart,domain) "
                           "from stdin with binary", this );
    List<Address>::Iterator i( asked );
    while ( i ) {
        if ( !i->id() ) {
            q->bind( 1, i->uname() );
            q->bind( 2, i->localpart() );
            q->bind( 3, i->domain() );
            q->submitLine();
            any = true;
        }
        ++i;
    }
    if ( any )
        return q;
    return 0;
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
