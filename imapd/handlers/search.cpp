// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "search.h"

#include "list.h"
#include "imap.h"
#include "messageset.h"
#include "imapsession.h"
#include "codec.h"
#include "query.h"
#include "log.h"
#include "message.h"


/*! \class Search search.h
    Finds messages matching some criteria (RFC 3501, §6.4.4)

    The entirety of the basic syntax is handled. CONDSTORE, SEARCHM
    and other extensions are currently not handled. SEARCHM probably
    will need to be implemented as a subclass of Search.

    Searches are first run against the RAM cache, rudimentarily. If
    the comparison is difficult, expensive or unsuccessful, it gives
    up and uses the database.
*/

class SearchData {
public:
    SearchData()
        : uid( false ), done( false ), root( 0 ), conditions( 0 ),
          codec( 0 ), query( 0 )
    {}

    bool uid;
    bool done;
    String charset;
    Search::Condition * root;
    List< Search::Condition > * conditions;
    List< uint > matches;

    Codec * codec;
    Query * query;
};

/*! Constructs an empty Search. If \a u is true, it's an UID SEARCH,
    otherwise it's the MSN variety.
*/

Search::Search( bool u )
    : d( new SearchData )
{
    d->uid = u;
}


void Search::parse()
{
    space();
    parseKey( true );
    if ( !d->charset.isEmpty() ) {
        space();
        parseKey();
    }
    while ( nextChar() == ' ' ) {
        space();
        parseKey();
    }
    end();

    prepare();
    respond( "OK debug: query as parsed: " + d->root->debugString() );
    log( "OK debug: query as parsed: " + d->root->debugString(), Log::Debug );
    d->root->simplify();
    respond( "OK debug: simplified query: " + d->root->debugString() );
    log( "OK debug: simplified query: " + d->root->debugString(), Log::Debug );
}


/*! Parse one search key (IMAP search-key). Leaves the cursor on the
    first character following the search-key. If \a alsoCharset is
    specified and true, the CHARSET modifier is handled. The default
    is to not handle CHARSET, since it's illegal except at the start.
*/

void Search::parseKey( bool alsoCharset )
{
    char c = nextChar();
    if ( c == '(' ) {
        // it's an "and" list.
        push( And );
        do {
            step();
            parseKey();
            c = nextChar();
        } while ( c == ' ' );
        if ( c != ')' )
            error( Bad, "')' expected, saw: " + following() );
        step();
        pop();
    }
    else if ( c == '*' || ( c >= '0' && c <= '9' ) ) {
        // it's a pure set
        add( set( true ) );
    }
    else {
        // first comes a keyword. they all are letters only, so:
        String keyword = letters( 2, 15 ).lower();
        if ( keyword == "all" ) {
            add( NoField, All );
        }
        else if ( keyword == "answered" ) {
            add( Flags, Contains, "answered" );
        }
        else if ( keyword == "deleted" ) {
            add( Flags, Contains, "deleted" );
        }
        else if ( keyword == "flagged" ) {
            add( Flags, Contains, "flagged" );
        }
        else if ( keyword == "new" ) {
            push( And );
            add( Flags, Contains, "recent" );
            add( Flags, Contains, "seen" );
            pop();
        }
        else if ( keyword == "old" ) {
            push( Not );
            add( Flags, Contains, "recent" );
            pop();
        }
        else if ( keyword == "recent" ) {
            add( Flags, Contains, "recent" );
        }
        else if ( keyword == "seen" ) {
            add( Flags, Contains, "seen" );
        }
        else if ( keyword == "unanswered" ) {
            push( Not );
            add( Flags, Contains, "answered" );
            pop();
        }
        else if ( keyword == "undeleted" ) {
            push( Not );
            add( Flags, Contains, "deleted" );
            pop();
        }
        else if ( keyword == "unflagged" ) {
            push( Not );
            add( Flags, Contains, "flagged" );
            pop();
        }
        else if ( keyword == "unseen" ) {
            push( Not );
            add( Flags, Contains, "seen" );
            pop();
        }
        else if ( keyword == "draft" ) {
            add( Flags, Contains, "draft" );
        }
        else if ( keyword == "undraft" ) {
            push( Not );
            add( Flags, Contains, "draft" );
            pop();
        }
        else if ( keyword == "on" ) {
            space();
            add( InternalDate, OnDate, date() );
        }
        else if ( keyword == "before" ) {
            add( InternalDate, BeforeDate, date() );
        }
        else if ( keyword == "since" ) {
            space();
            add( InternalDate, SinceDate, date() );
        }
        else if ( keyword == "sentbefore" ) {
            space();
            add( Sent, BeforeDate, date() );
        }
        else if ( keyword == "senton" ) {
            space();
            add( Sent, OnDate, date() );
        }
        else if ( keyword == "sentsince" ) {
            space();
            add( Sent, SinceDate, date() );
        }
        else if ( keyword == "from" ) {
            space();
            add( Header, Contains, "from", uastring() );
        }
        else if ( keyword == "to" ) {
            space();
            add( Header, Contains, "to", uastring() );
        }
        else if ( keyword == "cc" ) {
            space();
            add( Header, Contains, "cc", uastring() );
        }
        else if ( keyword == "bcc" ) {
            space();
            add( Header, Contains, "bcc", uastring() );
        }
        else if ( keyword == "subject" ) {
            space();
            add( Header, Contains, "subject", uastring() );
        }
        else if ( keyword == "body" ) {
            space();
            add( Body, Contains, "", uastring() );
        }
        else if ( keyword == "text" ) {
            space();
            UString a = uastring();
            push( Or );
            add( Body, Contains, "", a );
            // field name is null for any-field searches
            add( Header, Contains, 0, a );
            pop();
        }
        else if ( keyword == "keyword" ) {
            space();
            add( Flags, Contains, atom() );
        }
        else if ( keyword == "unkeyword" ) {
            space();
            push( Not );
            add( Flags, Contains, atom() );
            pop();
        }
        else if ( keyword == "header" ) {
            space();
            String s1 = astring();
            space();
            UString s2 = uastring();
            add( Header, Contains, s1, s2 );
        }
        else if ( keyword == "uid" ) {
            space();
            add( set( false ) );
        }
        else if ( keyword == "or" ) {
            space();
            push( Or );
            parseKey();
            space();
            parseKey();
            pop();
        }
        else if ( keyword == "not" ) {
            space();
            push( Not );
            parseKey();
            pop();
        }
        else if ( keyword == "larger" ) {
            space();
            add( Rfc822Size, Larger, number() );
        }
        else if ( keyword == "smaller" ) {
            space();
            add( Rfc822Size, Smaller, number() );
        }
        else if ( alsoCharset && keyword == "charset" ) {
            space();
            d->charset = astring();
            d->codec = Codec::byName( d->charset );
            if ( d->codec == 0 )
                error( No, "[BADCHARSET] Unknown character encoding: " +
                       d->charset );
        }
        else {
            error( Bad, "unknown search key: " + keyword );
        }
    }

    alsoCharset = false;
}


void Search::execute()
{
    // for now, we know there are no messages in there, so this is
    // correct:
    if ( !d->query ) {
        considerCache();
        if ( !d->done ) {
            //d->query = new Query( d->root->where( this ) );
            // this is where I do clever d->query->bind() stuff and then
            // execute
        }
    }

    if ( !d->done )
        return;

    ImapSession * s = imap()->session();
    String r( "SEARCH" );
    List<uint>::Iterator it = d->matches.first();
    while ( it ) {
        r.append( " " );
        uint n = *it;
        ++it;
        if ( !d->uid )
            n = s->msn( n );
        r.append( fn( n ) );
    }
    respond( r );
    setState( Finished );
}



/*! Considers whether this search can and should be solved using this
    cache, and if so, finds all the matches.
*/

void Search::considerCache()
{
    ImapSession * s = imap()->session();
    uint msn = s->count();
    bool needDb = false;
    uint c = 1;
    while ( c <= msn && !needDb ) {
        uint uid = s->uid( c );
        Message * m = s->message( uid );
        switch ( d->root->match( m, uid ) ) {
        case Search::Condition::Yes:
            d->matches.append( new uint( uid ) );
            break;
        case Search::Condition::No:
            break;
        case Search::Condition::Punt:
            log( "Search must go to database: message " + fn( uid ) +
                 " could not be tested in RAM", Log::Debug );
            needDb = true;
            break;
        }
        if ( !needDb )
            c++;
    }
    log( "Search considered " + fn( c ) + " of " + fn( c ) +
         " messages using cache, " + fn( d->matches.count() ) +
         " matches", Log::Debug );
    if ( needDb )
        d->matches.clear();
    else
        d->done = true;
}



/*! Parses the IMAP date production and returns the string (sans
    quotes). Month names are case-insensitive; RFC 3501 is not
    entirely clear about that. */

String Search::date()
{
    // date-day "-" date-month "-" date-year
    char c = nextChar();
    bool q = false;
    if ( c == '"' ) {
        step();
        q = true;
        c = nextChar();
    }
    String result;
    result.append( digits( 1, 2 ) );
    if ( nextChar() != '-' )
        error( Bad, "expected -, saw " + following() );
    result.append( "-" );
    step();
    String month = letters( 3, 3 ).lower();
    if ( month == "jan" || month == "feb" || month == "mar" ||
         month == "apr" || month == "may" || month == "jun" ||
         month == "jul" || month == "aug" || month == "sep" ||
         month == "oct" || month == "nov" || month == "dec" )
        result.append( month );
    else
        error( Bad, "Expected three-letter month name, received " + month );
    if ( nextChar() != '-' )
        error( Bad, "expected -, saw " + following() );
    result.append( "-" );
    step();
    result.append( digits( 4, 4 ) );
    if ( q ) {
        if ( nextChar() != '"' )
            error( Bad, "Expected \", saw " + following() );
        else
            step();
    }
    return result;
}


/*! This private helper adds a new Condition to the current list. \a
    f, \a a and \a a1 are used as-is. a2 is set to an empty string.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Search::Condition * Search::add( Field f, Action a,
                                 const String & a1 )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->f = f;
    c->a = a;
    c->a1 = a1;
    d->conditions->first()->l->append( c );
    return c;
}


/*! This private helper adds a new Condition to the current list. \a
    f, \a a, \a a1 and \a a2 are used as-is.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Search::Condition * Search::add( Field f, Action a,
                                 const String & a1, const UString & a2 )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->f = f;
    c->a = a;
    c->a1 = a1;
    c->a2 = a2;
    d->conditions->first()->l->append( c );
    return c;
}


/*! This private helper adds a new Condition to the current list. \a
    f, \a a and \a n are used as-is.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Search::Condition * Search::add( Field f, Action a, uint n )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->f = f;
    c->a = a;
    c->n = n;
    d->conditions->first()->l->append( c );
    return c;
}


/*! This private helper adds a new Condition to the current list,
    constraining the list to \a set.

*/

Search::Condition * Search::add( const MessageSet & set )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->f = Uid;
    c->a = Contains;
    c->s = set;
    d->conditions->first()->l->append( c );
    return c;
}


/*! Creates a new logical Condition, adds it to the current list if
    there is one, and pushes a new current list on the stack.

    \a a must be And, Or or Not. This isn't checked.
*/

Search::Condition * Search::push( Action a )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->a = a;
    c->l = new List<Condition>;
    if ( d->conditions->first() )
        d->conditions->first()->l->append( c );
    d->conditions->prepend( c );
    return c;
}


/*! Removes the current list of Conditions from the stack. The list
    can still be referenced - it is the list of arguments in the new
    top.
*/

void Search::pop()
{
    d->conditions->take( d->conditions->first() );
}


/*! This private helper takes care that invariants aren't broken. It
    should mostly be a noop, but in cases of syntax errors, it is
    perhaps possible that we might segfault without this function.
*/

void Search::prepare()
{
    if ( !d->conditions )
        d->conditions = new List<Condition>;
    if ( !d->conditions->isEmpty() )
        return;

    Condition * c = new Condition;
    c->c = this;
    c->a = And;
    c->l = new List<Condition>;
    d->conditions->prepend( c );

    if ( !d->root )
        d->root = c;
}


/*! \class Search::Condition search.h

    The Search::Condition class represents a single condition in a
    search, which is either a leaf condition or an AND/OR operator.

    The class can simplify() and regularize itself, such that all
    equivalent search inputs give the same result, and and it can
    express itself in a form amenable to testing. Rather simple.
*/


/*! This helper transforms this search conditions and all its children
    into a simpler form, if possible. There are two goals to this:

    1. Provide a regular search expression, so that we can eventually
    detect and prepare statements for often-repeated searches.

    2. Ditto, so that we can test that equivalent input gives
    identical output.

*/

void Search::Condition::simplify()
{
    // not (not x) -> x
    if ( a == Not && l->first()->a == Not ) {
        Condition * again = l->first()->l->first();

        f = again->f;
        a = again->a;
        a1 = again->a1;
        a2 = again->a2;
        s = again->s;
        n = again->n;
        l = again->l;
    }

    if ( a == Larger && n == 0 ) {
        // > 0 matches everything
        a = All;
    }
    else if ( a == Contains && f != Uid && a1.isEmpty() ) {
        // contains empty string too
        a = All;
    }
    else if ( a == Contains && f == Uid ) {
        if ( s.isEmpty() )
            a = None; // contains a set of nonexistent messages
        else if ( s.where() == "uid>=1" )
            a = All; // contains any messages at all
    }
    else if ( a == And ) {
        // zero-element and becomes all, "none and x" becomes none
        List< Condition >::Iterator i = l->first();
        while ( i && a == And ) {
            List< Condition >::Iterator p = i;
            ++i;
            p->simplify();
            if ( p->a == All )
                l->take( p );
            else if ( p->a == None )
                a = None;
        }
        if ( a == And && l->isEmpty() )
            a = All;

    }
    else if ( a == Or ) {
        // zero-element or becomes all, "all or x" becomes all
        List< Condition >::Iterator i = l->first();
        while ( i && a == Or ) {
            List< Condition >::Iterator p = i;
            ++i;
            p->simplify();
            if ( p->a == None )
                l->take( p );
            else if ( p->a == All )
                a = All;
        }
        if ( a == And && l->isEmpty() )
            a = All;

    }
    if ( a != And && a != Or )
        return;

    // an empty and/or means everything matches
    if ( l->isEmpty() ) {
        a = All;
        return;
    }

    // or (a or (b c)) -> or (a b c). ditto and.
    if ( l ) {
        List< Condition >::Iterator i = l->first();
        while ( i ) {
            List< Condition >::Iterator p = i;
            ++i;
            if ( p->a == a ) {
                List<Condition>::Iterator c = p->l->first();
                while ( c ) {
                    l->prepend( c );
                    c++;
                }
                l->take( p );
            }
        }
    }

    // a single-element and/or can be removed and its argument substituted
    if ( l->count() == 1 ) {
        List< Condition >::Iterator p = l->first();
        f = p->f;
        a = p->a;
        a1 = p->a1;
        a2 = p->a2;
        s = p->s;
        l = p->l;
        return;
    }

    // at this point, for proper uniqueness, we ought to sort the
    // children, killing any duplicates in the process. then we'll
    // have a single query for each job. but that can wait. this will
    // do for testing.
}


/*! Give an ASCII representatation of this object, suitable for debug
    output or for equality testing.
*/

String Search::Condition::debugString() const
{
    String r;

    String o, w;

    switch ( a ) {
    case OnDate:
        o = "on";
        break;
    case SinceDate:
        o = "since";
        break;
    case BeforeDate:
        o = "before";
        break;
    case Contains:
        o = "contains";
        break;
    case Larger:
        o = "larger";
        break;
    case Smaller:
        o = "smaller";
        break;
    case And:
    case Or:
        break;
    case Not:
        return "not " + l->first()->debugString();
    case All:
        return "all";
        break;
    case None:
        return "none";
        break;
    };

    if ( o.isEmpty() ) {
        r = "(";
        List< Condition >::Iterator i = l->first();
        while ( i ) {
            r += i->debugString();
            ++i;
            if ( i ) {
                if ( a == And )
                    r += " and ";
                else
                    r += " or ";
            }
        }
        r += ")";
        return r;
    }

    switch( f ) {
    case InternalDate:
        w = "delivery";
        break;
    case Sent:
        w = "sent";
        break;
    case Header:
        if ( a1.isEmpty() )
            w = "header";
        else
            w = "header field " + a1;
        break;
    case Body:
        w = "body";
        break;
    case Rfc822Size:
        w = "rfc822 size";
        break;
    case Flags:
        w = "set of flags";
        break;
    case NoField:
        w = "none";
        break;
    case Uid:
        return s.where();
        break;
    };

    r = w + " " + o + " ";
    if ( a2.isEmpty() )
        r.append( a1 );
    else
        r.append( a2.ascii() );

    return r;

}


/*! Matches \a m against this condition, provided the match is
    reasonably simple and quick, and returns either Yes, No, or (if
    the match is difficult, expensive or depends on data that isn't
    available) Punt.
*/

Search::Condition::MatchResult Search::Condition::match( Message * m,
                                                         uint uid )
{
    if ( a == And || a == Or ) {
        List< Condition >::Iterator i = l->first();
        while ( i ) {
            MatchResult sub = i->match( m, uid );
            if ( sub == Punt )
                return Punt;
            if ( a == And && sub == No )
                return No;
            if ( a == Or && sub == Yes )
                return Yes;
            ++i;
        }
        if ( a == And )
            return Yes;
        else
            return No;
    }
    else if ( a == Contains && f == Uid ) {
        if ( s.contains( uid ) )
            return Yes;
        return No;
    }
    else if ( a == Contains && f == Flags ) {
        if ( uid > 0 && a1 == "recent" ) {
            ImapSession * s = c->imap()->session();
            if ( s->isRecent( uid ) )
                return Yes;
            return No;
        }
        else if ( m ) {
            if ( a1 == "answered" )
                return m->flag( Message::AnsweredFlag ) ? Yes : No;
            if ( a1 == "deleted" )
                return m->flag( Message::DeletedFlag ) ? Yes : No;
            if ( a1 == "draft" )
                return m->flag( Message::DraftFlag ) ? Yes : No;
            if ( a1 == "flagged" )
                return m->flag( Message::FlaggedFlag ) ? Yes : No;
            if ( a1 == "seen" )
                return m->flag( Message::SeenFlag ) ? Yes : No;
        }

        return Punt;
    }
    else if ( a == Not ) {
        MatchResult sub = l->first()->match( m, uid );
        if ( sub == Punt )
            return Punt;
        else if ( sub == Yes )
            return No;
        else
            return Yes;
    }
    else if ( a == All ) {
        return Yes;
    }

    return Punt;
}


/*! Reads an astring and returns it as unicode, using the charset
    specified in the CHARSET argument to SEARCH.
*/

UString Search::uastring()
{
    if ( !d->codec )
        d->codec = new AsciiCodec;

    String raw = astring();
    UString canon = d->codec->toUnicode( raw );
    if ( d->codec->valid() )
        error( Bad,
               "astring not valid under encoding " + d->codec->name() +
               ": " + raw );
    return canon;
}
