// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "search.h"

#include "imapsession.h"
#include "messageset.h"
#include "mailbox.h"
#include "message.h"
#include "codec.h"
#include "query.h"
#include "date.h"
#include "imap.h"
#include "flag.h"
#include "list.h"
#include "log.h"
#include "utf.h"


class SearchQuery: public Query {
public:
    SearchQuery( EventHandler * e ): Query( e ) {}
    String string() const { return s; }
    String s;
};


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
          codec( 0 ), query( 0 ), argc( 0 ), mboxId( 0 ),
          usesHeaderFieldsTable( false ),
          usesFieldNamesTable( false ),
          usesAddressFieldsTable( false ),
          usesAddressesTable( false ),
          usesPartNumbersTable( false ),
          usesBodypartsTable( false ),
          usesFlagsTable( false ),
          usesFlagNamesTable( false )
    {}

    bool uid;
    bool done;
    String charset;
    Search::Condition * root;
    List< Search::Condition > * conditions;

    Codec * codec;
    SearchQuery * query;

    uint argc;
    uint argument() {
        ++argc;
        return argc;
    };
    uint mboxId;

    bool usesHeaderFieldsTable;
    bool usesFieldNamesTable;
    bool usesAddressFieldsTable;
    bool usesAddressesTable;
    bool usesPartNumbersTable;
    bool usesBodypartsTable;
    bool usesFlagsTable;
    bool usesFlagNamesTable;
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
    log( "OK debug: query as parsed: " + d->root->debugString(), Log::Debug );
    d->root->simplify();
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
            add( Flags, Contains, "\\answered" );
        }
        else if ( keyword == "deleted" ) {
            add( Flags, Contains, "\\deleted" );
        }
        else if ( keyword == "flagged" ) {
            add( Flags, Contains, "\\flagged" );
        }
        else if ( keyword == "new" ) {
            push( And );
            add( Flags, Contains, "\\recent" );
            add( Flags, Contains, "\\seen" );
            pop();
        }
        else if ( keyword == "old" ) {
            push( Not );
            add( Flags, Contains, "\\recent" );
            pop();
        }
        else if ( keyword == "recent" ) {
            add( Flags, Contains, "\\recent" );
        }
        else if ( keyword == "seen" ) {
            add( Flags, Contains, "\\seen" );
        }
        else if ( keyword == "unanswered" ) {
            push( Not );
            add( Flags, Contains, "\\answered" );
            pop();
        }
        else if ( keyword == "undeleted" ) {
            push( Not );
            add( Flags, Contains, "\\deleted" );
            pop();
        }
        else if ( keyword == "unflagged" ) {
            push( Not );
            add( Flags, Contains, "\\flagged" );
            pop();
        }
        else if ( keyword == "unseen" ) {
            push( Not );
            add( Flags, Contains, "\\seen" );
            pop();
        }
        else if ( keyword == "draft" ) {
            add( Flags, Contains, "\\draft" );
        }
        else if ( keyword == "undraft" ) {
            push( Not );
            add( Flags, Contains, "\\draft" );
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
        if ( d->done ) {
            finish();
            return;
        }

        d->query = new SearchQuery( this );
        d->mboxId = d->argument();
        d->query->bind( d->mboxId, imap()->session()->mailbox()->id() );
        d->query->s = "select distinct messages.uid from messages";
        String w( d->root->where() );
        if ( !ok() )
            return;
        if ( d->usesHeaderFieldsTable )
            d->query->s.append( ", header_fields" );
        if ( d->usesFieldNamesTable )
            d->query->s.append( ", field_names" );
        if ( d->usesAddressFieldsTable )
            d->query->s.append( ", address_fields" );
        if ( d->usesAddressesTable )
            d->query->s.append( ", addresses" );
        if ( d->usesPartNumbersTable )
            d->query->s.append( ", part_numbers" );
        if ( d->usesBodypartsTable )
            d->query->s.append( ", bodyparts" );
        if ( d->usesFlagNamesTable )
            d->query->s.append( ", flag_names" );
        d->query->s.append( " where messages.mailbox=$" + fn( d->mboxId ) +
                            " and (" + w + ") order by messages.uid" );
        d->query->execute();
    }

    if ( !d->query->done() )
        return;

    if ( d->query->failed() ) {
        error( No, "Database error: " + d->query->error() );
        return;
    }

    ImapSession * s = imap()->session();
    Row * r;
    String result( "SEARCH" );
    while ( (r=d->query->nextRow()) != 0 ) {
        uint n = r->getInt( "uid" );
        if ( !d->uid )
            n = s->msn( n );
        result.append( " " );
        result.append( fn( n ) );
    }

    respond( result );
    finish();
}



/*! Considers whether this search can and should be solved using this
    cache, and if so, finds all the matches.
*/

void Search::considerCache()
{
    ImapSession * s = imap()->session();
    uint msn = s->count();
    bool needDb = false;
    uint c = 0;
    String matches = "SEARCH";
    while ( c < msn && !needDb ) {
        c++;
        uint uid = s->uid( c );
        Message * m = s->mailbox()->message( uid, false );
        switch ( d->root->match( m, uid ) ) {
        case Search::Condition::Yes:
            matches.append( " " );
            if ( d->uid )
                matches.append( fn( c ) );
            else
                matches.append( fn( uid ) );
            break;
        case Search::Condition::No:
            break;
        case Search::Condition::Punt:
            log( "Search must go to database: message " + fn( uid ) +
                 " could not be tested in RAM",
                 Log::Debug );
            needDb = true;
            break;
        }
    }
    log( "Search considered " + fn( c ) + " of " + fn( c ) +
         " messages using cache", Log::Debug );
    if ( !needDb ) {
        respond( matches );
        d->done = true;
    }
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
    f, \a a and \a s8 are used as-is. s16 is set to an empty string.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Search::Condition * Search::add( Field f, Action a,
                                 const String & s8 )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->d = d;
    c->f = f;
    c->a = a;
    c->s8 = s8;
    d->conditions->first()->l->append( c );
    return c;
}


/*! This private helper adds a new Condition to the current list. \a
    f, \a a, \a s8 and \a s16 are used as-is.

    This function isn't well-defined for cases where \a a is And, Or
    or Not.
*/

Search::Condition * Search::add( Field f, Action a,
                                 const String & s8, const UString & s16 )
{
    prepare();
    Condition * c = new Condition;
    c->c = this;
    c->d = d;
    c->f = f;
    c->a = a;
    if ( f == Header )
        c->s8 = s8.headerCased();
    else
        c->s8 = s8;
    c->s16 = s16;
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
    c->d = d;
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
    c->d = d;
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
    c->d = d;
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
    d->conditions->shift();
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
    c->d = d;
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
    into a simpler form, if possible. There are three goals to this:

    1. Provide a regular search expression, so that we can eventually
    detect and prepare statements for often-repeated searches.

    2. Ditto, so that we can test that equivalent input gives
    identical output.

    3. Avoid search expressions which would be horribly inefficient or
    just plain impossible for the RDBMS.
*/

void Search::Condition::simplify()
{
    // not (not x) -> x
    if ( a == Not && l->first()->a == Not ) {
        Condition * again = l->first()->l->first();

        f = again->f;
        a = again->a;
        s8 = again->s8;
        s16 = again->s16;
        s = again->s;
        n = again->n;
        l = again->l;
    }

    if ( a == Contains && f == Flags && s8.lower() == "\\recent" ) {
        // the database cannot look at UIDs, so we turn this query
        // into a test for the relevant UIDs.
        f = Uid;
        s = c->imap()->session()->recent();
        // later we may simplify this again
    }

    if ( a == Larger && n == 0 ) {
        // > 0 matches everything
        a = All;
    }
    else if ( a == Contains ) {
        // x contains y may match everything
        switch ( f ) {
        case InternalDate:
        case Sent:
            a = None;
            break;
        case Header:
        case Body:
            if ( s16.isEmpty() )
                a = All;
            break;
        case Rfc822Size:
            break;
        case Flags:
            if ( !Flag::find( s8 ) )
                a = None;
            break;
        case Uid:
            // if s contains all messages or is empty...
            if ( s.isEmpty() )
                a = None;
            // the All Messages case is harder.
            break;
        case NoField:
            // contains is orthogonal to nofield, so this we cannot
            // simplify
            break;
        }
        // contains empty string too
    }
    else if ( a == Contains && f == Uid ) {
        if ( s.isEmpty() )
            a = None; // contains a set of nonexistent messages
        else if ( s.where() == "uid>=1" )
            a = All; // contains any messages at all
    }
    else if ( a == And ) {
        // zero-element and becomes all, "none and x" becomes none
        List< Condition >::Iterator i( l );
        while ( i && a == And ) {
            List< Condition >::Iterator p( i );
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
        List< Condition >::Iterator i( l );
        while ( i && a == Or ) {
            List< Condition >::Iterator p( i );
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
    if ( a == All || a == None )
        f = NoField;

    if ( a != And && a != Or )
        return;

    // an empty and/or means everything matches
    if ( l->isEmpty() ) {
        a = All;
        return;
    }

    // or (a or (b c)) -> or (a b c). ditto and.
    if ( l ) {
        List< Condition >::Iterator i( l );
        while ( i ) {
            List< Condition >::Iterator p( i );
            ++i;
            if ( p->a == a ) {
                List<Condition>::Iterator c( p->l );
                while ( c ) {
                    l->prepend( c );
                    ++c;
                }
                l->take( p );
            }
        }
    }

    // a single-element and/or can be removed and its argument substituted
    if ( l->count() == 1 ) {
        List< Condition >::Iterator p( l );
        f = p->f;
        a = p->a;
        s8 = p->s8;
        s16 = p->s16;
        s = p->s;
        l = p->l;
        return;
    }

    // at this point, for proper uniqueness, we ought to sort the
    // children, killing any duplicates in the process. then we'll
    // have a single query for each job. but that can wait. this will
    // do for testing.
}


/*! Gives an SQL string representing this condition.

    The string may include $n placeholders; where() and its helpers
    will bind them as required.
*/

String Search::Condition::where() const
{
    switch( f ) {
    case InternalDate:
        return whereInternalDate();
        break;
    case Sent:
        return whereSent();
        break;
    case Header:
        if ( s8.isEmpty() )
            return whereHeader();
        else
            return whereHeaderField();
        break;
    case Body:
        return whereBody();
        break;
    case Rfc822Size:
        return whereRfc822Size();
        break;
    case Flags:
        return whereFlags();
        break;
    case Uid:
        return whereUid();
        break;
    case NoField:
        return whereNoField();
        break;
    }
    c->error( Command::No, "Internal error for " + debugString() );
    return "";
}

/*! This implements the INTERNALDATE part of where().
*/

String Search::Condition::whereInternalDate() const
{
    uint day = s8.mid( 0, 2 ).number( 0 );
    String month = s8.mid( 3, 3 );
    uint year = s8.mid( 7 ).number( 0 );
    // XXX: local time zone is ignored here
    Date d1;
    d1.setDate( year, month, day, 0, 0, 0, 0 );
    Date d2;
    d2.setDate( year, month, day, 23, 59, 59, 0 );
    uint n1 = d->argument();
    d->query->bind( n1, d1.unixTime() );
    uint n2 = d->argument();
    d->query->bind( n2, d2.unixTime() );

    if ( a == OnDate ) {
        return "messages.idate>=$" + fn( n1 ) +
            " and messages.idate<=$" + fn( n2 );
    }
    else if ( a == SinceDate ) {
        return "messages.idate>=$" + fn( n1 );
    }
    else if ( a == BeforeDate ) {
        return "messages.idate<=$" + fn( n2 );
    }
    c->error( Command::No, "Cannot search for: " + debugString() );
    return "";
}

/*! This implements the SENTON/SENTBEFORE/SENTSINCE part of where().
*/

String Search::Condition::whereSent() const
{
    c->error( Command::No,
              "Searching on the Date field unimplemented, sorry" );
    return "";
}


static String q( const UString & orig )
{
    Utf8Codec c;
    String r( c.fromUnicode( orig ) );
    // escape % somehow?
    return r;
}


/*! This implements searches on a single header field.
*/

String Search::Condition::whereHeaderField() const
{
    uint f = 1;
    while ( f <= HeaderField::LastAddressField &&
            HeaderField::fieldName( (HeaderField::Type)f ) != s8 )
        f++;
    if ( f <= HeaderField::LastAddressField )
        return whereAddressField( s8 );

    uint fnum = d->argument();
    d->query->bind( fnum, s8 );
    uint like = d->argument();
    d->query->bind( like, q( s16 ) );
    d->usesHeaderFieldsTable = true;
    d->usesFieldNamesTable = true;
    return "header_fields.mailbox=messages.mailbox and "
        "header_fields.uid=messages.uid and "
        "header_fields.field=field_names.id and "
        "field_names.name=$" + fn( fnum ) + " and "
        "value like '%' || $" + fn( like ) + " || '%'";
}


/*! This implements searches on the single address field \a field, or
    on all address fields if \a field is empty. \a d as usual.
*/

String Search::Condition::whereAddressField( const String & field ) const
{
    String raw( q( s16 ) );
    int at = raw.find( '@' );
    d->usesAddressFieldsTable = true;
    d->usesAddressesTable = true;
    String r;
    r.append( "address_fields.mailbox=messages.mailbox and "
              "address_fields.uid=messages.uid " );
    if ( !field.isEmpty() ) {
        d->usesFieldNamesTable = true;
        uint fnum = d->argument();
        d->query->bind( fnum, s8 );
        r.append( "and address_fields.field=field_names.id and "
                  "field_names.name=$" + fn( fnum ) );
    }
    r.append( " and address_fields.address=addresses.id" );
    if ( at < 0 ) {
        uint name = d->argument();
        d->query->bind( name, raw );
        r.append( " and "
                  "(addresses.name like '%'||$" + fn( name ) + "||'%' "
                  "or addresses.localpart ilike '%'||$" + fn( name ) + "||'%' "
                  "or addresses.domain ilike '%'||$" + fn( name ) + "||'%')" );
    }
    else {
        String lc, dc;
        if ( at > 0 ) {
            uint lp = d->argument();
            if ( raw.startsWith( "<" ) ) {
                d->query->bind( lp, raw.mid( 1, at-1 ) );
                lc = "addresses.localpart ilike $" + fn( lp );
            }
            else {
                d->query->bind( lp, raw.mid( 0, at ) );
                lc = "addresses.localpart ilike '%'||$" + fn( lp ) + " ";
            }
        }
        if ( at < (int)raw.length() - 1 ) {
            uint dom = d->argument();
            if ( raw.endsWith( ">" ) ) {
                d->query->bind( dom, raw.mid( at+1, raw.length()-at-2 ) );
                dc = "addresses.domain ilike $" + fn( dom );
            }
            else {
                d->query->bind( dom, raw.mid( at+1 ) );
                dc = "addresses.domain ilike $" + fn( dom ) + "||'%'";
            }
        }
        if ( lc.isEmpty() && dc.isEmpty() ) {
            // imap SEARCH FROM "@" matches messages with a nonempty
            // from field. the sort of thing only a test suite would
            // do.
        }
        if ( !lc.isEmpty() ) {
            r.append( " and " );
            r.append( lc );
        }
        if ( !dc.isEmpty() ) {
            r.append( " and " );
            r.append( dc );
        }
    }
    return r;
}

/*! This implements searches on all header fields.
*/

String Search::Condition::whereHeader() const
{
    uint like = d->argument();
    d->query->bind( like, q( s16 ) );
    d->usesHeaderFieldsTable = true;
    return "(header_fields.mailbox=messages.mailbox and "
        "header_fields.uid=messages.uid and "
        "value like '%'||$" + fn( like ) + "||'%') or (" +
        whereAddressField() + ")";
}


/*! This implements searches on (text) bodyparts. We cannot and will
    not do "full-text" search on the contents of e.g. jpeg
    pictures. (For some formats we search on the text part, because
    the injector sets bodyparts.text based on bodyparts.data.)
*/

String Search::Condition::whereBody() const
{
    uint bt = d->argument();
    d->query->bind( bt, q( s16 ) );
    d->usesPartNumbersTable = true;
    d->usesBodypartsTable = true;
    return "messages.mailbox=part_numbers.mailbox and "
        "messages.uid=part_numbers.uid and "
        "part_numbers.bodypart=bodyparts.id and "
        "bodyparts.text like '%'||$" + fn( bt ) + "||'%'";
}


/*! This implements searches on the rfc822size of messages.
*/

String Search::Condition::whereRfc822Size() const
{
    uint s = d->argument();
    d->query->bind( s, n );
    if ( a == Smaller )
        return "messages.rfc822size<$" + fn( s );
    else if ( a == Larger )
        return "messages.rfc822size>$" + fn( s );
    c->error( Command::No, "Internal error: " + debugString() );
    return "";
}


/*! This implements searches on whether a message has/does not have
    flags.
*/

String Search::Condition::whereFlags() const
{
    // the database can look in the ordinary way. we make it easy, if we can.
    d->usesFlagsTable = true;
    Flag * f = Flag::find( s8 );
    uint name = d->argument();
    if ( f ) {
        d->query->bind( name, f->id() );
        return "messages.uid in ("
            "select uid from flags where flags.mailbox=$" + fn( d->mboxId ) +
            " and flags.flag=$" + fn( name ) + ")";
    }
    d->usesFlagNamesTable = true;
    d->query->bind( name, s8 ); // do we need to smash case on flags?
    return "messages.uid in ("
        "select flags.uid from flags, flag_names "
        "where flags.mailbox=$" + fn( d->mboxId ) +
        " and flags.flag=flag_names.id and flag_names.name=$" +
        fn( name ) + ")";
}


/*! This implements searches on whether a message has the right UID.
*/

String Search::Condition::whereUid() const
{
    return s.where( "messages" );
}


/*! This implements any search that's not bound to a specific field,
    generally booleans and "all".
*/

String Search::Condition::whereNoField() const
{
    if ( a == And || a == Or ) {
        if ( l->isEmpty() ) {
            if ( a == And )
                return "true";
            return "false";
        }
        List<Condition>::Iterator i( l );
        String r = "(" + i->where();
        ++i;
        String sep;
        if ( a == And )
            sep = ") and (";
        else
            sep = ") or (";
        while ( i ) {
            r.append( sep );
            r.append( i->where() );
            ++i;
        }
        r.append( ")" );
        return r;
    }
    else if ( a == Not ) {
        return "not (" + l->first()->where() + ")";
    }
    else if ( a == All ) {
        return "true";
    }
    else if ( a == None ) {
        return "false";
    }
    c->error( Command::No, "Internal error: " + debugString() );
    return "";
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
        List< Condition >::Iterator i( l );
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
        if ( s8.isEmpty() )
            w = "header";
        else
            w = "header field " + s8;
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
    if ( s16.isEmpty() )
        r.append( s8 );
    else
        r.append( s16.ascii() );

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
        List< Condition >::Iterator i( l );
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
        if ( uid > 0 && s8 == "recent" ) {
            ImapSession * s = c->imap()->session();
            if ( s->isRecent( uid ) )
                return Yes;
            return No;
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
    if ( !d->codec->valid() )
        error( Bad,
               "astring not valid under encoding " + d->codec->name() +
               ": " + raw );
    return canon;
}
