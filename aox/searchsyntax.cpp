// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "searchsyntax.h"

#include "selector.h"

#include "field.h"
#include "codec.h"
#include "utf.h"

#include <stdio.h> // fprintf, stderr


static UString address( const EString & i, const char * & e )
{
    EString r = i;
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
    AsciiCodec ac;
    return ac.toUnicode( r );
}


static UString domain( const EString & i, const char * & e )
{
    EString r = i;
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
    AsciiCodec ac;
    return ac.toUnicode( r );
}


static Selector * parseSelector( EStringList * arguments,
                                 bool paren, const char * & e )
{
    Selector * s = 0;
    List<Selector> children;
    bool seenAnd = false;
    bool seenOr = false;
    bool seenNot = false;
    EString * i = arguments->shift();
    while ( i && !e ) {
        EString * n = arguments->firstElement();
        EString a = i->lower();
        if ( a == "not" ) {
            seenNot = true;
            i = arguments->shift();
            n = arguments->firstElement();
            if ( !i )
                e = "NOT as last argument";
            else
                a = i->lower();
        }
        Selector * c = 0;

        if ( a == "(" ) {
            children.append( parseSelector( arguments, true, e ) );
            if ( arguments->firstElement() )
                fprintf( stderr, "next first: %s\n",
                         arguments->firstElement()->cstr() );
            else
                fprintf( stderr, "child parser consumed everything\n" );
        }
        else if ( a == "from" ||
             a == "to" ||
             a == "cc" ||
             a == "reply-to" ||
             a == "address" ) {
            if ( !n ) {
                e = "No address supplied";
            }
            else if ( n->contains( "@" ) ) {
                if ( a == "address" ) {
                    c = new Selector( Selector::Or );
                    HeaderField::Type t = HeaderField::From;
                    while ( t <= HeaderField::LastAddressField ) {
                        c->add( new Selector( Selector::Header,
                                              Selector::Contains,
                                              HeaderField::fieldName( t ),
                                              address( *n, e ) ) );
                        t = (HeaderField::Type)(1+(uint)t);
                    }
                }
                else {
                    c = new Selector( Selector::Header,
                                      Selector::Contains,
                                      a, address( *n, e ) );
                }
                arguments->shift();
            }
            else if ( n->contains( "." ) ) {
                if ( a == "address" ) {
                    c = new Selector( Selector::Or );
                    HeaderField::Type t = HeaderField::From;
                    while ( t <= HeaderField::LastAddressField ) {
                        c->add( new Selector( Selector::Header,
                                              Selector::Contains,
                                              HeaderField::fieldName( t ),
                                              domain( *n, e ) ) );
                        t = (HeaderField::Type)(1+(uint)t);
                    }
                }
                else {
                    c = new Selector( Selector::Header,
                                      Selector::Contains,
                                      a, domain( *n, e ) );
                }
                arguments->shift();
            }
            else {
                e = "Address search argument must be "
                    "local@doma.in or doma.in";
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
            if ( !n ) {
                e = "No header field substring supplied";
            }
            else {
                Utf8Codec uc;
                c = new Selector( Selector::Header,
                                  Selector::Contains,
                                  a, uc.toUnicode( *n ) );
                arguments->shift();
            }
        }
        else if ( a == "text" ) {
            if ( !n ) {
                e = "No body substring supplied";
            }
            else {
                Utf8Codec uc;
                c = new Selector( Selector::Body,
                                  Selector::Contains,
                                  uc.toUnicode( *n ) );
                arguments->shift();
            }
        }
        else if ( a == "older" || a == "younger" ) {
            bool ok = false;
            uint limit = 0;
            if ( n )
                limit = n->number( &ok );
            if ( !ok ) {
                e = "Message age must be given as a number of days";
            }
            else if ( a == "younger" ) {
                c = new Selector( Selector::Age, Selector::Smaller, limit );
                arguments->shift();
            }
            else {
                c = new Selector( Selector::Age, Selector::Larger, limit );
                arguments->shift();
            }
        }
        else if ( a == "flag" ) {
            if ( n ) {
                EString h = n->lower();
                while ( h.startsWith( "\\") )
                    h = h.mid( 1 );
                if ( h == "deleted" )
                    h = "\\Deleted";
                else if ( h == "answered" )
                    h = "\\Answered";
                else if ( h == "flagged" )
                    h = "\\Flagged";
                else if ( h == "draft" )
                    h = "\\Draft";
                else if ( h == "seen" )
                    h = "\\Seen";
                c = new Selector( Selector::Flags, Selector::Contains, h );
                arguments->shift();
            }
            else {
                e = "Must have a flag name";
            }
        }
        else {
            e = "Bad argument";
        }

        if ( c ) {
            if ( seenNot ) {
                Selector * n = new Selector( Selector::Not );
                n->add( c );
                children.append( n );
            }
            else {
                children.append( c );
            }
        }

        if ( arguments->isEmpty() ) {
            i = 0;
        }
        else if ( !e ) {
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

    List<Selector>::Iterator c( children );
    while ( c ) {
        s->add( c );
        ++c;
    }
    return s;
}


Selector * parseSelector( EStringList * arguments )
{
    const char * e = 0;
    Selector * s = parseSelector( arguments, false, e );
    if ( !e )
        return s;

    fprintf( stderr, "While parsing search arguments: %s\n", e );
    if ( !arguments->isEmpty() )
        fprintf( stderr, "Error happened near: %s\n",
                 arguments->firstElement()->cstr() );

    return 0;
}
