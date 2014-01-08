// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "search.h"

#include "searchsyntax.h"

#include "selector.h"
#include "mailbox.h"

#include <stdio.h> // fprintf, stderr


void dumpSelector( Selector * s, uint l )
{
    EString a;
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
    case Selector::MailboxTree:
        if ( s->alsoChildren() )
            a = "Message is in subtree: ";
        else
            a = "Message is in mailbox: ";
        a.append( s->mailbox()->name().ascii() );
        break;
    case Selector::InThread:
        a = "A message in the same thread matches:";
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
                " (" + EString::humanNumber( s->integerArgument() ) + ")";
        else
            a = "Message is larger than " + fn( s->integerArgument() ) +
                " (" + EString::humanNumber( s->integerArgument() ) + ")";
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
    case Selector::DatabaseId:
        a = "Message's database ID is " +
            fn( s->integerArgument() );
        break;
    case Selector::ThreadId:
        a = "Message's thread ID is " +
            fn( s->integerArgument() );
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


static AoxFactory<ShowSearch>
f( "show", "search", "Parse and explain the effects of a search expression",
   "    Synopsis: show search <search>\n\n"
   "    Parses the search expression and explains (in a different way) what\n"
   "    it does. This is a good way to experiment with searches before using\n"
   "    e.g. aox undelete.\n" );


/*! \class ShowSearch search.h

    The ShowSearch class parses a search expression and then explains
    what the search expression does in a different format. It's meant
    to help people formulate searches for use with other aox commands,
    and also to help us test.
*/

ShowSearch::ShowSearch( EStringList * args )
    : AoxCommand( args )
{
    parseOptions();
    Selector * s = parseSelector( args );
    if ( !s )
        return;
    EString sqlFormat = s->string();
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
        EStringList wanted;
        wanted.append( "mailbox" );
        wanted.append( "uid" );

        Query * q = s->query( 0, 0, 0, 0, false, &wanted, false );
        if ( q ) {
            EString qs = q->string();
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
