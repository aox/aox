#include "search.h"

#include "list.h"
#include "set.h"
#include "imap.h"


class SearchD
{
public:
    SearchD() : uid( false ), query( 0 ), conditions( 0 ) {}

    bool uid;
    Query * query;
    List<Query::Condition> * conditions;
    String charset;
};

/*! \class Search

    \brief The Search class handles IMAP SEARCH commands.

    The entirety of the basic syntax is handled. CONDSTORE, SEARCHM
    and other extensions are currently not handled. SEARCHM probably
    will need to be implemented as a subclass of Search.
*/


/*! Constructs an empty Search. If \a u is true, it's an UID SEARCH,
    otherwise it's the MSN variety.
*/

Search::Search( bool u )
    : d( new SearchD )
{
    d->uid = u;
}


void Search::parse()
{
    prepare();

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
    d->query = new Query( d->conditions->last() );
    respond( "OK original: " + d->query->debugString() );
    d->query->simplify();
    respond( "OK simplified: " + d->query->debugString() );
}


/*! Parse one search key (IMAP search-key). Leaves the cursor on the
    first character following the search-key.
*/

void Search::parseKey( bool alsoCharset )
{
    char c = nextChar();
    if ( c == '(' ) {
        // it's an "and" list.
        push( Query::And );
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
            add( Query::NoField, Query::All );
        }
        else if ( keyword == "answered" ) {
            add( Query::Flags, Query::Contains, "answered" );
        }
        else if ( keyword == "deleted" ) {
            add( Query::Flags, Query::Contains, "deleted" );
        }
        else if ( keyword == "flagged" ) {
            add( Query::Flags, Query::Contains, "flagged" );
        }
        else if ( keyword == "new" ) {
            add( Query::Flags, Query::Contains, "recent" );
            add( Query::Flags, Query::Contains, "seen" );
        }
        else if ( keyword == "old" ) {
            push( Query::Not );
            add( Query::Flags, Query::Contains, "recent" );
            pop();
        }
        else if ( keyword == "recent" ) {
            add( Query::Flags, Query::Contains, "recent" );
        }
        else if ( keyword == "seen" ) {
            add( Query::Flags, Query::Contains, "seen" );
        }
        else if ( keyword == "unanswered" ) {
            push( Query::Not );
            add( Query::Flags, Query::Contains, "answered" );
            pop();
        }
        else if ( keyword == "undeleted" ) {
            push( Query::Not );
            add( Query::Flags, Query::Contains, "deleted" );
            pop();
        }
        else if ( keyword == "unflagged" ) {
            push( Query::Not );
            add( Query::Flags, Query::Contains, "flagged" );
            pop();
        }
        else if ( keyword == "unseen" ) {
            push( Query::Not );
            add( Query::Flags, Query::Contains, "seen" );
            pop();
        }
        else if ( keyword == "draft" ) {
            add( Query::Flags, Query::Contains, "draft" );
        }
        else if ( keyword == "undraft" ) {
            push( Query::Not );
            add( Query::Flags, Query::Contains, "draft" );
            pop();
        }
        else if ( keyword == "on" ) {
            space();
            add( Query::InternalDate, Query::OnDate, date() );
        }
        else if ( keyword == "before" ) {
            add( Query::InternalDate, Query::BeforeDate, date() );
        }
        else if ( keyword == "since" ) {
            space();
            add( Query::InternalDate, Query::SinceDate, date() );
        }
        else if ( keyword == "sentbefore" ) {
            space();
            add( Query::Sent, Query::BeforeDate, date() );
        }
        else if ( keyword == "senton" ) {
            space();
            add( Query::Sent, Query::OnDate, date() );
        }
        else if ( keyword == "sentsince" ) {
            space();
            add( Query::Sent, Query::SinceDate, date() );
        }
        else if ( keyword == "from" ) {
            space();
            add( Query::Header, Query::Contains, "from", astring() );
        }
        else if ( keyword == "to" ) {
            space();
            add( Query::Header, Query::Contains, "to", astring() );
        }
        else if ( keyword == "cc" ) {
            space();
            add( Query::Header, Query::Contains, "cc", astring() );
        }
        else if ( keyword == "bcc" ) {
            space();
            add( Query::Header, Query::Contains, "bcc", astring() );
        }
        else if ( keyword == "subject" ) {
            space();
            add( Query::Header, Query::Contains, "subject", astring() );
        }
        else if ( keyword == "body" ) {
            space();
            add( Query::Body, Query::Contains, astring() );
        }
        else if ( keyword == "text" ) {
            space();
            String a = astring();
            push( Query::Or );
            add( Query::Body, Query::Contains, a );
            add( Query::Header, Query::Contains, 0, a ); // field name is null
            pop();
        }
        else if ( keyword == "keyword" ) {
            space();
            add( Query::Flags, Query::Contains, atom() );
        }
        else if ( keyword == "unkeyword" ) {
            space();
            push( Query::Not );
            add( Query::Flags, Query::Contains, atom() );
            pop();
        }
        else if ( keyword == "header" ) {
            space();
            String s1 = astring();
            space();
            String s2 = astring();
            add( Query::Header, Query::Contains, s1, s2 );
        }
        else if ( keyword == "uid" ) {
            space();
            add( set( false ) );
        }
        else if ( keyword == "or" ) {
            space();
            push( Query::Or );
            parseKey();
            space();
            parseKey();
            pop();
        }
        else if ( keyword == "not" ) {
            space();
            push( Query::Not );
            parseKey();
            pop();
        }
        else if ( keyword == "larger" ) {
            space();
            add( Query::Rfc822Size, Query::Larger, number() );
        }
        else if ( keyword == "smaller" ) {
            space();
            add( Query::Rfc822Size, Query::Smaller, number() );
        }
        else if ( alsoCharset && keyword == "charset" ) {
            space();
            d->charset = astring();
            // xxx: check that the name is valid
        }
        else {
            error( Bad, "unknown search-key: " + keyword );
        }
    }

    alsoCharset = false;
}




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
    f, \a a and \a a1 are used as-is.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Query::Condition * Search::add( Query::Field f, Query::Action a,
                                const String & a1, const String & a2 )
{
    prepare();
    Query::Condition * c = new Query::Condition;
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

Query::Condition * Search::add( Query::Field f, Query::Action a, uint n )
{
    prepare();
    Query::Condition * c = new Query::Condition;
    c->f = f;
    c->a = a;
    c->n = n;
    d->conditions->first()->l->append( c );
    return c;
}


/*! This private helper adds a new Condition to the current list,
    constraining the list to \a set.

*/

Query::Condition * Search::add( const Set & set )
{
    prepare();
    Query::Condition * c = new Query::Condition;
    c->f = Query::Uid;
    c->a = Query::Contains;
    c->s = set;
    d->conditions->first()->l->append( c );
    return c;
}


/*! Creates a new logical Condition, adds it to the current list if
    there is one, and pushes a new current list on the stack.

    \a must be And, Or or Not. This isn't checked.
*/

Query::Condition * Search::push( Query::Action a )
{
    prepare();
    Query::Condition * c = new Query::Condition;
    c->a = a;
    c->l = new List<Query::Condition>;
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
    perhaps possible that we might segfault without this function. Any
    inefficiency caused by this function is repaired by
    Query::simplify().
*/

void Search::prepare()
{
    if ( !d->conditions )
        d->conditions = new List<Query::Condition>;
    if ( d->conditions->isEmpty() ) {
        Query::Condition * c = new Query::Condition;
        c->a = Query::And;
        c->l = new List<Query::Condition>;
        d->conditions->prepend( c );
    }
}
