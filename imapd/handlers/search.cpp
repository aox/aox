#include "search.h"

#include "list.h"
#include "imap.h"
#include "messageset.h"
#include "codec.h"


/*! \class Search search.h
    Finds messages matching some criteria (RFC 3501, §6.4.4)

    The entirety of the basic syntax is handled. CONDSTORE, SEARCHM
    and other extensions are currently not handled. SEARCHM probably
    will need to be implemented as a subclass of Search.

    Searches are first run against the RAM cache, rudimentarily. If
    the comparison is difficult, expensive or unsuccessful, it gives
    up and uses the database.
*/

class SearchD
{
public:
    SearchD() : uid( false ), conditions( 0 ), root( 0 ), codec( 0 ) {}

    bool uid;
    List<Search::Condition> * conditions;
    Search::Condition * root;
    String charset;
    Codec * codec;
};

/*! Constructs an empty Search. If \a u is true, it's an UID SEARCH,
    otherwise it's the MSN variety.
*/

Search::Search( bool u )
    : d( new SearchD )
{
    d->uid = u;
}


/*! \reimp */

void Search::parse()
{
    prepare();

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
    d->root->simplify();
    respond( "OK debug: simplified query: " + d->root->debugString() );
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
            add( Flags, Contains, "recent" );
            add( Flags, Contains, "seen" );
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
            add( Header, Contains, "from", astring() );
        }
        else if ( keyword == "to" ) {
            space();
            add( Header, Contains, "to", astring() );
        }
        else if ( keyword == "cc" ) {
            space();
            add( Header, Contains, "cc", astring() );
        }
        else if ( keyword == "bcc" ) {
            space();
            add( Header, Contains, "bcc", astring() );
        }
        else if ( keyword == "subject" ) {
            space();
            add( Header, Contains, "subject", astring() );
        }
        else if ( keyword == "body" ) {
            space();
            add( Body, Contains, astring() );
        }
        else if ( keyword == "text" ) {
            space();
            String a = astring();
            push( Or );
            add( Body, Contains, a );
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
            String s2 = astring();
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
                error( No, "Unknown character encoding: " + d->charset );
        }
        else {
            error( Bad, "unknown search key: " + keyword );
        }
    }

    alsoCharset = false;
}




/*! \reimp */

void Search::execute()
{
    // for now, we know there are no messages in there, so this is
    // correct:
    respond( "SEARCH " );
    // easy.
    setState( Finished );
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
    f, \a a, \a a1 and \a a2 are used as-is.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Search::Condition * Search::add( Field f, Action a,
                                   const String & a1, const String & a2 )
{
    prepare();
    Condition * c = new Condition;
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
        r.append( a2 );

    return r;

}
