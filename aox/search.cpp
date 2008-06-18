// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "selector.h"

#include "codec.h"
#include "utf.h"

#include <stdio.h> // fprintf, stderr


static UString address( const String & i, const char * & e )
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
    AsciiCodec ac;
    return ac.toUnicode( r );
}


static UString domain( const String & i, const char * & e )
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
    AsciiCodec ac;
    return ac.toUnicode( r );
}


static Selector * parseSelector( StringList * arguments,
                                 bool paren, const char * & e )
{
    Selector * s = 0;
    List<Selector> children;
    bool seenAnd = false;
    bool seenOr = false;
    bool seenNot = false;
    String * i = arguments->shift();
    while ( i && !e ) {
        String * n = arguments->firstElement();
        String a = i->lower();
        if ( a == "(" ) {
            children.append( parseSelector( arguments, true, e ) );
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
                children.append( new Selector( Selector::Header,
                                               Selector::Contains,
                                               a, address( *n, e ) ) );
            }
            else if ( n->contains( "." ) ) {
                children.append( new Selector( Selector::Header,
                                               Selector::Contains,
                                               a, domain( *n, e ) ) );
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
            if ( !n ) {
                e = "No header field substring supplied";
            }
            else {
                Utf8Codec c;
                children.append( new Selector( Selector::Header,
                                               Selector::Contains,
                                               a, c.toUnicode( *n ) ) );
            }
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

    List<Selector>::Iterator c( children );
    while ( c ) {
        s->add( c );
        ++c;
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


void dumpSelector( Selector * s, uint l )
{
    String a;
    bool children = false;

    switch( s->field() ) {
    case Selector::InternalDate:
        if ( s->action() == Selector::OnDate )
            a = "Message arrived on: " + s->stringArgument();
        else if ( s->action() == Selector::SinceDate )
            a = "Message arrived on or after: " + s->stringArgument();
        else if ( s->action() == Selector::BeforeDate )
            a = "Message arrived on or before: " + s->stringArgument();
        break;
    case Selector::Sent:
        if ( s->action() == Selector::OnDate )
            a = "Message was sent on: " + s->stringArgument();
        else if ( s->action() == Selector::SinceDate )
            a = "Message was sent on or after: " + s->stringArgument();
        else if ( s->action() == Selector::BeforeDate )
            a = "Message was sent on or before: " + s->stringArgument();
        break;
    case Selector::Header:
        if ( s->stringArgument().isEmpty() )
            a = "Any header field contains: " +
                s->ustringArgument().utf8().quoted();
        else
            a = "Header field " + s->stringArgument().quoted() +
                " contains: " + s->ustringArgument().utf8().quoted();
        break;
    case Selector::Body:
        a = "Body text contains: " + s->stringArgument().quoted();
        break;
    case Selector::Rfc822Size:
        if ( s->action() == Selector::Smaller )
            a = "Message is smaller than " + fn( s->integerArgument() ) +
                " (" + String::humanNumber( s->integerArgument() ) + ")";
        else
            a = "Message is larger than " + fn( s->integerArgument() ) +
                " (" + String::humanNumber( s->integerArgument() ) + ")";
        break;
    case Selector::Flags:
        a = "Message has flag: " + s->stringArgument().quoted();
        break;
    case Selector::Uid:
        a = "Message has UID: " + s->messageSetArgument().set();
        break;
    case Selector::Annotation:
        a = "Message annotation " + s->stringArgument().quoted() +
            " contains: " + s->ustringArgument().utf8().quoted();
        break;
    case Selector::Modseq:
        if ( s->action() == Selector::Smaller )
            a = "Message's modseq is smaller than " +
                fn( s->integerArgument() );
        else
            a = "Message's modseq is larger than " +
                fn( s->integerArgument() );
        break;
    case Selector::Age:
        if ( s->action() == Selector::Smaller )
            a = "Message id younger than " +
                fn( s->integerArgument() ) + " days";
        else
            a = "Message id older than " +
                fn( s->integerArgument() ) + " days";
        break;
    case Selector::NoField:
        children = true;
        if ( s->action() == Selector::And )
            a = "All must be true:";
        else if ( s->action() == Selector::And )
            a = "Any must be true:";
        else if ( s->action() == Selector::And )
            a = "Not";
        else
            children = false;
        break;
    }

    if ( !a.isEmpty() )
        fprintf( stdout, " %*s%s\n", l*2, "", a.cstr() );

    if ( !children )
        return;
    
    List<Selector>::Iterator i( s->children() );
    while ( i ) {
        Selector * c = i;
        ++i;
        dumpSelector( c, l+1 );
    }
}


void dumpSelector( Selector * s )
{
    dumpSelector( s, 0 );
}


