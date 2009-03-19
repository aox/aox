// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "search.h"

#include "selector.h"

#include "field.h"
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


Selector * parseSelector( StringList * arguments )
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
            a = "Header field " + s->stringArgument().quoted().headerCased() +
                " contains: " + s->ustringArgument().utf8().quoted();
        break;
    case Selector::Body:
        a = "Body text contains: " + s->ustringArgument().utf8().quoted();
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
            a = "Message is younger than " +
                fn( s->integerArgument() ) + " days";
        else
            a = "Message is older than " +
                fn( s->integerArgument() ) + " days";
        break;
    case Selector::NoField:
        children = true;
        if ( s->action() == Selector::And )
            a = "All must be true:";
        else if ( s->action() == Selector::Or )
            a = "Any must be true:";
        else if ( s->action() == Selector::Not )
            a = "Not:";
        else
            children = false;
        break;
    }

    if ( !a.isEmpty() )
        fprintf( stdout, "%*s%s\n", l*2, "", a.cstr() );

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




/*! \class ShowSearch search.h

    The ShowSearch class parses a search expression and then explains
    what the search expression does in a different format. It's meant
    to help people formulate searches for use with other aox commands,
    and also to help us test.
*/

ShowSearch::ShowSearch( StringList * args )
    : AoxCommand( args )
{
    parseOptions();
    Selector * s = parseSelector( args );
    if ( !s )
        return;
    String sqlFormat = s->string();
    Selector * stored = Selector::fromString( sqlFormat );
    if ( stored->string() != s->string() )
        fprintf( stderr,
                 "Error: Round-trip coversion to/from db format failed\n" );
    dumpSelector( s );
    s->simplify();
    if ( sqlFormat != s->string() ) {
        fprintf( stdout,
                 "Search could be simplified. Showing simplified form:\n" );
        dumpSelector( s );
    }
    if ( opt( 's' ) ) {
        StringList wanted;
        wanted.append( "mailbox" );
        wanted.append( "uid" );

        Query * q = s->query( 0, 0, 0, 0, false, &wanted, false );
        if ( q ) {
            String qs = q->string();
            qs.replace( " from", "\n  from" );
            qs.replace( " join", "\n  join" );
            qs.replace( " left\n  join", "\n  left join" );
            qs.replace( " where", "\n  where" );
            qs.replace( "\n", "\n  " );
            fprintf( stdout, "Showing generic SQL form:\n  %s\n", qs.cstr() );
        }
    }
}


void ShowSearch::execute()
{
    // nothing yet - may one day carry out a search
    finish();
}
