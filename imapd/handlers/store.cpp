/*! \class Store store.h
    \brief STORE alters message metadata (RFC 3501, §6.4.6).
*/

#include "store.h"

#include "set.h"


/*  store           = "STORE" SP set SP store-att-flags
    store-att-flags = (["+" / "-"] "FLAGS" [".SILENT"]) SP
                      (flag-list / (flag *(SP flag)))

    flag-list       = "(" [flag *(SP flag)] ")"
    flag            = "\Answered" / "\Flagged" / "\Deleted" / "\Seen" /
                      "\Draft" / flag-keyword / flag-extension

    flag-keyword    = atom
    flag-extension  = "\" atom
*/

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
    if ( present( ".silent" ) )
        silent = true;
    space();

    bool parens = false;
    if ( present( "(" ) )
        parens = true;

    do {
        if ( flags.count() > 0 )
            step();

        String * flag = new String;

        if ( present( "\\" ) )
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

    if ( parens && !present( ")" ) )
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
