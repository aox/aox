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

    item = letters( 5, 5 );
    if ( item != "flags" )
        error( Bad, "Unknown item: " + item );

    if ( nextChar() == '.' ) {
        step();
        String suffix = letters( 6, 6 );
        if ( suffix == "silent" )
            silent = true;
        else
            error( Bad, "Unknown suffix: " + suffix );
    }
    
    space();

    bool parens = false;
    if ( nextChar() == '(' ) {
        parens = true;
        step();
    }

    do {
        if ( flags.count() > 0 )
            step();

        String * flag = new String;
        char c = nextChar();

        if ( c == '\\' ) {
            step();
            flag->append( c );
            c = nextChar();
        }

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
    
    if ( parens && nextChar() != ')' )
        error( Bad, "" );
    else
        step();

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

    response.append( " " + item + " " );

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
