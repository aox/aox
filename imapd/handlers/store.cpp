/*! \class Store store.h
    \brief STORE (RFC 3501, §6.4.6)
*/

#include "store.h"

#include "set.h"


void Store::parse()
{
    s = set( true );
    space();

    op = Replace;
    char pm = nextChar();
    if ( pm == '-' || pm == '+' ) {
        op = ( pm == '+' ) ? Add : Remove ;
        step();
    }

    require( "flags" );
    if ( skip( ".silent" ) )
        silent = true;
    space();

    bool parens = false;
    if ( skip( '(' ) )
        parens = true;

    do {
        if ( flags.count() > 0 )
            step();

        String * flag = new String;

        if ( skip( '\\' ) )
            flag->append( '\\' );

        char c = nextChar();
        while ( c > ' ' && c < 127 &&
                c != '(' && c != ')' && c != '{' &&
                c != ']' &&
                c != '"' && c != '\\' &&
                c != '%' && c != '*' )
        {
            flag->append( c );
            step();
            c = nextChar();
        }

        flags.append( flag );
    } while ( nextChar() == ' ' );

    if ( parens && !skip( ')' ) )
        error( Bad, "" );

    end();
}


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
