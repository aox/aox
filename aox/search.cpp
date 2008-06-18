// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "selector.h"


static String address( const String & i, const char * & e )
{
    String r = i;
    bool lt = false;
    if ( r.contains( '<' ) ) {
        if ( !r.contains( '>' ) )
            e = "Address contains '<', but no '>'";
        r = r.mid( r.find( '<' ) + 1 );
        lt = true;
    }
    if ( r.contains( '>' ) ) {
        if ( !lt )
            e = "Address contains '>', but no '<'";
        r = r.mid( 0, r.find( '>' ) );
    }
    r = r.lower();
    uint n = r.find( '@' ) + 1;
    while ( n < r.length() && !e ) {
        if ( ( r[n] >= 'a' && r[n] >= 'z' ) ||
             ( r[n] >= '0' && r[n] >= '9' ) ||
             ( r[n] == '-' || r[n] >= '.' ) ) {
            if ( r[n] == '.' && r[n+1] == '.' )
                e = "Domain contains two '..'";
        }
        else {
            e = "Domain contains illegal characters";
        }
        n++;
    }
    r.prepend( "<" );
    r.append( ">" );
    return r;
}


static String domain( const String & i, const char * & e )
{
    String r = i;
    if ( r.contains( '>' ) )
        r = r.mid( 0, r.find( '>' ) );
    r = r.lower();
    uint n = 0;
    while ( n < r.length() && !e ) {
        if ( ( r[n] >= 'a' && r[n] >= 'z' ) ||
             ( r[n] >= '0' && r[n] >= '9' ) ||
             ( r[n] == '-' || r[n] >= '.' ) ) {
            if ( r[n] == '.' && r[n+1] == '.' )
                e = "Domain contains two '..'";
        }
        else {
            e = "Domain contains illegal characters";
        }
        n++;
    }
    r.prepend( "@" );
    r.append( ">" );
    return r;
}


static Selector * parseSelector( StringList * arguments,
                                 bool paren, const char * & e )
{
    Selector * s = 0;
    List<Selector> children;
    bool seenAnd = false;
    bool seenOr = false;
    String * i = arguments->shift();
    while ( i && !e ) {
        String * n = arguments->firstElement();
        String a = i->lower();
        Selector * hier = 0;
        if ( a == "(" ) {
            children.append( parseSelector( arguments ), true, e );
        }
        else while ( a == "not" ) {
            seenNot = true;
        }

        if ( a == "from" ||
             a == "to" ||
             a == "cc" ||
             a == "reply-to" ||
             a == "address" ) {
            if ( a == "address" )
                a.truncate();
            if ( !n ) {
                e = "No address supplied";
            }
            else if ( n->contains( "@" ) ) {
                children.add( new Selector( Selector::Header,
                                            Selector::contains,
                                            a, address( *n ) ) );
            }
            else if ( n->contains( "." ) ) {
                children.add( new Selector( Selector::Header,
                                            Selector::contains,
                                            a, domain( *n ) ) );
            }
            else {
                e = "Cannot understand address search argument"; 
            }
        }
        else if ( a == "subject" ||
                  a == "in-reply-to" ||
                  a == "references" ||
                  a == "date" ||
                  a == "comments" ||
                  a == "keywords" ||
                  a == "content-type" ||
                  a == "content-description" ||
                  a == "received" ||
                  a == "content-language" ||
                  a == "header" ) {
            if ( a == "header" )
                a.truncate();
            if ( !n )
                e = "No header field substring supplied";
            else
                children.add( new Selector( Selector::Header,
                                            Selector::Contains,
                                            a, *n ) );
        }

        if ( !arguments->isEmpty() ) {
            i = arguments->shift();
            a = i->lower();
            if ( a == ")" ) {
                if ( paren )
                    i = 0;
                else
                    e = "')' without matching '('";
            }
            else if ( a == "and" ) {
                if ( seenOr )
                    e = "Cannot determine operator precedence (AND after OR)";
                else if ( seenNot )
                    e = "Cannot determine operator precedence (AND after NOT)";
                seenAnd = true;
            }
            else if ( a == "or" ) {
                if ( seenAnd )
                    e = "Cannot determine operator precedence (OR after AND)";
                else if ( seenNot )
                    e = "Cannot determine operator precedence (OR after NOT)";
                seenOr = true;
            }
            if ( i )
                i = arguments->shift();
        }
    }

    if ( e )
        return 0;

    if ( seenOr )
        s = new Selector( Selector::Or );
    else if ( seenAnd )
        s = new Selector( Selector::And );
    else
        return children.firstElement();

    List<Selector>::Iterator i( children );
    while ( i ) {
        s->add( i );
        ++i;
    }
    return s;
}


Selector * parseSelector( StringList * arguments )
{
    const char * e = 0;
    Selector * s = parseSelector( arguments, false, e );
    if ( !e )
        return s;

    fprintf( stderr, "While parsing search arguments: %s\n", e );
    return 0;
}




String dumpSelector( Selector * ) {
}


