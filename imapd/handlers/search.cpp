/*! \class Search search.h
    Finds messages matching some criteria (RFC 3501, §6.4.4)

    The entirety of the basic syntax is handled. CONDSTORE, SEARCHM
    and other extensions are currently not handled. SEARCHM probably
    will need to be implemented as a subclass of Search.
*/

#include "search.h"

#include "list.h"
#include "imap.h"
#include "messageset.h"


class SearchD
{
public:
    SearchD() : uid( false ), query( 0 ), conditions( 0 ) {}

    bool uid;
    NotQuery * query;
    List<NotQuery::Condition> * conditions;
    String charset;
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
    d->query = new NotQuery( d->conditions->last() );
    respond( "OK original: " + d->query->debugString() );
    d->query->simplify();
    respond( "OK simplified: " + d->query->debugString() );
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
        push( NotQuery::And );
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
            add( NotQuery::NoField, NotQuery::All );
        }
        else if ( keyword == "answered" ) {
            add( NotQuery::Flags, NotQuery::Contains, "answered" );
        }
        else if ( keyword == "deleted" ) {
            add( NotQuery::Flags, NotQuery::Contains, "deleted" );
        }
        else if ( keyword == "flagged" ) {
            add( NotQuery::Flags, NotQuery::Contains, "flagged" );
        }
        else if ( keyword == "new" ) {
            add( NotQuery::Flags, NotQuery::Contains, "recent" );
            add( NotQuery::Flags, NotQuery::Contains, "seen" );
        }
        else if ( keyword == "old" ) {
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, "recent" );
            pop();
        }
        else if ( keyword == "recent" ) {
            add( NotQuery::Flags, NotQuery::Contains, "recent" );
        }
        else if ( keyword == "seen" ) {
            add( NotQuery::Flags, NotQuery::Contains, "seen" );
        }
        else if ( keyword == "unanswered" ) {
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, "answered" );
            pop();
        }
        else if ( keyword == "undeleted" ) {
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, "deleted" );
            pop();
        }
        else if ( keyword == "unflagged" ) {
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, "flagged" );
            pop();
        }
        else if ( keyword == "unseen" ) {
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, "seen" );
            pop();
        }
        else if ( keyword == "draft" ) {
            add( NotQuery::Flags, NotQuery::Contains, "draft" );
        }
        else if ( keyword == "undraft" ) {
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, "draft" );
            pop();
        }
        else if ( keyword == "on" ) {
            space();
            add( NotQuery::InternalDate, NotQuery::OnDate, date() );
        }
        else if ( keyword == "before" ) {
            add( NotQuery::InternalDate, NotQuery::BeforeDate, date() );
        }
        else if ( keyword == "since" ) {
            space();
            add( NotQuery::InternalDate, NotQuery::SinceDate, date() );
        }
        else if ( keyword == "sentbefore" ) {
            space();
            add( NotQuery::Sent, NotQuery::BeforeDate, date() );
        }
        else if ( keyword == "senton" ) {
            space();
            add( NotQuery::Sent, NotQuery::OnDate, date() );
        }
        else if ( keyword == "sentsince" ) {
            space();
            add( NotQuery::Sent, NotQuery::SinceDate, date() );
        }
        else if ( keyword == "from" ) {
            space();
            add( NotQuery::Header, NotQuery::Contains, "from", astring() );
        }
        else if ( keyword == "to" ) {
            space();
            add( NotQuery::Header, NotQuery::Contains, "to", astring() );
        }
        else if ( keyword == "cc" ) {
            space();
            add( NotQuery::Header, NotQuery::Contains, "cc", astring() );
        }
        else if ( keyword == "bcc" ) {
            space();
            add( NotQuery::Header, NotQuery::Contains, "bcc", astring() );
        }
        else if ( keyword == "subject" ) {
            space();
            add( NotQuery::Header, NotQuery::Contains, "subject", astring() );
        }
        else if ( keyword == "body" ) {
            space();
            add( NotQuery::Body, NotQuery::Contains, astring() );
        }
        else if ( keyword == "text" ) {
            space();
            String a = astring();
            push( NotQuery::Or );
            add( NotQuery::Body, NotQuery::Contains, a );
            add( NotQuery::Header, NotQuery::Contains, 0, a ); // field name is null
            pop();
        }
        else if ( keyword == "keyword" ) {
            space();
            add( NotQuery::Flags, NotQuery::Contains, atom() );
        }
        else if ( keyword == "unkeyword" ) {
            space();
            push( NotQuery::Not );
            add( NotQuery::Flags, NotQuery::Contains, atom() );
            pop();
        }
        else if ( keyword == "header" ) {
            space();
            String s1 = astring();
            space();
            String s2 = astring();
            add( NotQuery::Header, NotQuery::Contains, s1, s2 );
        }
        else if ( keyword == "uid" ) {
            space();
            add( set( false ) );
        }
        else if ( keyword == "or" ) {
            space();
            push( NotQuery::Or );
            parseKey();
            space();
            parseKey();
            pop();
        }
        else if ( keyword == "not" ) {
            space();
            push( NotQuery::Not );
            parseKey();
            pop();
        }
        else if ( keyword == "larger" ) {
            space();
            add( NotQuery::Rfc822Size, NotQuery::Larger, number() );
        }
        else if ( keyword == "smaller" ) {
            space();
            add( NotQuery::Rfc822Size, NotQuery::Smaller, number() );
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

NotQuery::Condition * Search::add( NotQuery::Field f, NotQuery::Action a,
                                const String & a1, const String & a2 )
{
    prepare();
    NotQuery::Condition * c = new NotQuery::Condition;
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

NotQuery::Condition * Search::add( NotQuery::Field f, NotQuery::Action a, uint n )
{
    prepare();
    NotQuery::Condition * c = new NotQuery::Condition;
    c->f = f;
    c->a = a;
    c->n = n;
    d->conditions->first()->l->append( c );
    return c;
}


/*! This private helper adds a new Condition to the current list,
    constraining the list to \a set.

*/

NotQuery::Condition * Search::add( const MessageSet & set )
{
    prepare();
    NotQuery::Condition * c = new NotQuery::Condition;
    c->f = NotQuery::Uid;
    c->a = NotQuery::Contains;
    c->s = set;
    d->conditions->first()->l->append( c );
    return c;
}


/*! Creates a new logical Condition, adds it to the current list if
    there is one, and pushes a new current list on the stack.

    \a a must be And, Or or Not. This isn't checked.
*/

NotQuery::Condition * Search::push( NotQuery::Action a )
{
    prepare();
    NotQuery::Condition * c = new NotQuery::Condition;
    c->a = a;
    c->l = new List<NotQuery::Condition>;
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
    NotQuery::simplify().
*/

void Search::prepare()
{
    if ( !d->conditions )
        d->conditions = new List<NotQuery::Condition>;
    if ( d->conditions->isEmpty() ) {
        NotQuery::Condition * c = new NotQuery::Condition;
        c->a = NotQuery::And;
        c->l = new List<NotQuery::Condition>;
        d->conditions->prepend( c );
    }
}
