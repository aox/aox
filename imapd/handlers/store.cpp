#include "store.h"

#include "messageset.h"


/*! \class Store store.h
    Alters message flags (RFC 3501, §6.4.6).

    The Store command is the principal means of altering message flags,
    although Annotate may be able to do the same.
*/

/*!  Constructs a Store handler. If \a u is set, the first argument is
     presumed to be a UID set, otherwise it's an MSN set.
*/

Store::Store( bool u )
    : op( Replace), silent( false ), uid( u )
{
}


/*! \reimp */

void Store::parse()
{
    space();
    s = set( uid );
    space();

    op = Replace;
    if ( present( "-" ) )
        op = Remove;
    else if ( present( "+" ) )
        op = Add;

    require( "flags" );
    silent = present( ".silent" );
    space();

    bool parens = present( "(" );

    // XXX: This is broken. flag() (via atom()) will die when it sees an
    // empty list. I don't see how to handle that case nicely.
    do {
        flags.append( new String( flag() ) );
    } while ( present( " " ) );

    if ( parens )
        require( ")" );

    end();
}


/*! Reports the operation that would be performed, but does nothing so
    far.
*/

void Store::execute()
{
    String response;

    switch ( op ) {
    case Add:
        response.append( "Add" );
        break;
    case Remove:
        response.append( "Remove" );
        break;
    case Replace:
        response.append( "Replace" );
        break;
    }

    response.append( " flags " );

    List< String >::Iterator it = flags.first();
    while ( it ) {
        response.append( "("+*it+")" );
        it++;
    }

    if ( silent )
        response.append( " (silently)" );

    respond( "OK " + response );
    setState( Finished );
}
