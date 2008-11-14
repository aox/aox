// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "helperrowcreator.h"

#include "dict.h"
#include "allocator.h"
#include "transaction.h"
#include "query.h"

#include "annotationname.h"
#include "fieldname.h"
#include "flag.h"


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
    String n;
    String e;
    bool done;
    Dict<uint> names;
};


/*!  Constructs an empty HelperRowCreator refering to \a table, using
     \a transaction. If an error related to \a constraint occurs,
     execute() will roll back to a savepoint and try again.
*/

HelperRowCreator::HelperRowCreator( const String & table,
                                    Transaction * transaction,
                                    const String & constraint )
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
        if ( d->s && !d->s->done() )
            return;
        if ( d->c && !d->c->done() )
            return;

        if ( !d->s && !d->c ) {
            d->s = makeSelect();
            if ( d->s ) {
                if ( !d->t )
                    d->t = d->parent->subTransaction( this );
                d->t->enqueue( d->s );
                d->t->execute();
            }
            else {
                d->done = true;
            }
        }

        if ( d->s && d->s->done() && !d->c ) {
            processSelect( d->s );
            d->s = 0;
            d->c = makeCopy();
            if ( d->c ) {
                d->t->enqueue( d->c );
                String ed = d->n;
                ed.replace( "creator", "extended" );
                Query * q = new Query( "notify " + ed, this );
                d->t->enqueue( q );
                d->t->execute();
            }
            else {
                d->done = true;
            }
        }

        if ( d->c && d->c->done() ) {
            Query * c = d->c;
            d->c = 0;
            if ( !c->failed() ) {
                // We inserted, hit no race, and want to run another select.
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
    // the parent transaction's owne may have to wait for this creator
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
        add( r->getString( "name" ), r->getInt( "id" ) );
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

void HelperRowCreator::add( const String & s, uint id )
{
    uint * tmp = (uint *)Allocator::alloc( sizeof(uint), 0 );
    *tmp = id;

    d->names.insert( s.lower(), tmp );
}


/*! Returns the id stored earlier with add() for the name \a s. */

uint HelperRowCreator::id( const String & s )
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

FlagCreator::FlagCreator( const StringList & f, Transaction * t )
    : HelperRowCreator( "flag_names", t, "fn_uname" ),
      names( f )
{
}


Query * FlagCreator::makeSelect()
{
    Query * s = new Query( "select id, name from flag_names where "
                           "lower(name)=any($1::text[])", this );

    StringList sl;
    StringList::Iterator it( names );
    while ( it ) {
        String name( *it );
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
    StringList::Iterator it( names );
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


FieldNameCreator::FieldNameCreator( const StringList & f,
                                    Transaction * tr )
    : HelperRowCreator( "field_names", tr,  "field_names_name_key" ),
      names( f )
{
}


Query * FieldNameCreator::makeSelect()
{
    Query * q = new Query( "select id, name from field_names where "
                           "name=any($1::text[])", this );

    StringList sl;
    StringList::Iterator it( names );
    while ( it ) {
        if ( id( *it ) == 0 && FieldName::id( *it ) == 0 )
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
    StringList::Iterator it( names );
    bool any = false;
    while ( it ) {
        if ( id( *it ) == 0 && FieldName::id( *it ) == 0 ) {
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

AnnotationNameCreator::AnnotationNameCreator( const StringList & f,
                                              Transaction * t )
    : HelperRowCreator( "annotation_names", t, "annotation_names_name_key" ),
      names( f )
{
}

Query *  AnnotationNameCreator::makeSelect()
{
    Query * q = new Query( "select id, name from annotation_names where "
                           "name=any($1::text[])", this );

    StringList sl;
    StringList::Iterator it( names );
    while ( it ) {
        String name( *it );
        if ( id( name ) == 0 && AnnotationName::id( name ) == 0 )
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
    StringList::Iterator it( names );
    bool any = false;
    while ( it ) {
        if ( id( *it ) == 0 && AnnotationName::id( *it ) == 0 ) {
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
