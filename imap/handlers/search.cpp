// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "search.h"

#include "imapsession.h"
#include "imapparser.h"
#include "annotation.h"
#include "messageset.h"
#include "listext.h"
#include "mailbox.h"
#include "message.h"
#include "codec.h"
#include "query.h"
#include "date.h"
#include "imap.h"
#include "list.h"
#include "log.h"
#include "utf.h"


static const char * legalAnnotationAttributes[] = {
    "value",
    "value.priv",
    "value.shared",
    0
};


class SearchData
    : public Garbage
{
public:
    SearchData()
        : uid( false ), done( false ), codec( 0 ), root( 0 ),
          query( 0 ), highestmodseq( 1 ),
          firstmodseq( 1 ), lastmodseq( 1 ),
          returnModseq( false ),
          returnAll( false ), returnCount( false ),
          returnMax( false ), returnMin( false )
    {}

    bool uid;
    bool done;

    String charset;
    Codec * codec;

    Selector * root;

    Query * query;
    MessageSet matches;
    int64 highestmodseq;
    int64 firstmodseq;
    int64 lastmodseq;
    bool returnModseq;

    bool returnAll;
    bool returnCount;
    bool returnMax;
    bool returnMin;
};


/*! \class Search search.h
    Finds messages matching some criteria (RFC 3501 section 6.4.4)

    The entirety of the basic syntax is handled, as well as ESEARCH
    (RFC 4731 and RFC 4466) and parts of CONDSTORE (RFC 4551). SEARCHM
    probably will need to be implemented as a subclass of Search.

    Searches are first run against the RAM cache, rudimentarily. If
    the comparison is difficult, expensive or unsuccessful, it gives
    up and uses the database.

    If ESEARCH with only MIN, only MAX or only COUNT is used, we could
    generate better SQL than we do. Let's do that optimisation when a
    client benefits from it.
*/


/*! Constructs an empty Search. If \a u is true, it's a UID SEARCH,
    otherwise it's the MSN variety.
*/

Search::Search( bool u )
    : d( new SearchData )
{
    d->uid = u;
    if ( u )
        setGroup( 1 );
    else
        setGroup( 2 );

    d->root = new Selector;
}


void Search::parse()
{
    space();
    if ( present( "return" ) ) {
        // RFC 4731 and RFC 4466 define ESEARCH together.
        space();
        require( "(" );
        bool any = false;
        while ( ok() && nextChar() != ')' &&
                nextChar() >= 'A' && nextChar() <= 'z' ) {
            String modifier = letters( 3, 5 ).lower();
            any = true;
            if ( modifier == "all" )
                d->returnAll = true;
            else if ( modifier == "min" )
                d->returnMin = true;
            else if ( modifier == "max" )
                d->returnMax = true;
            else if ( modifier == "count" )
                d->returnCount = true;
            else
                error( Bad, "Unknown search modifier option: " + modifier );
            if ( nextChar() != ')' )
                space();
        }
        require( ")" );
        if ( !any )
            d->returnAll = true;
        space();
    }
    if ( present ( "charset" ) ) {
        space();
        setCharset( astring() );
        space();
    }
    d->root = new Selector;
    d->root->add( parseKey() );
    while ( ok() && !parser()->atEnd() ) {
        space();
        d->root->add( parseKey() );
    }
    end();

    d->returnModseq = d->root->usesModseq();
    d->root->simplify();
    log( "Search for " + d->root->debugString() );
}


/*! Parse one search key (IMAP search-key) and returns a pointer to
    the corresponding Selector. Leaves the cursor on the first
    character following the search-key.
*/

Selector * Search::parseKey()
{
    char c = nextChar();
    if ( c == '(' ) {
        step();
        // it's an "and" list.
        Selector * s = new Selector( Selector::And );
        s->add( parseKey() );
        while ( ok() && !present( ")" ) ) {
            space();
            s->add( parseKey() );
        }
        return s;
    }
    else if ( c == '*' || ( c >= '0' && c <= '9' ) ) {
        // it's a pure set
        return new Selector( set( true ) );
    }
    else if ( present( "all" ) ) {
        return new Selector( Selector::NoField, Selector::All );
    }
    else if ( present( "answered" ) ) {
        return new Selector( Selector::Flags, Selector::Contains, "\\answered" );
    }
    else if ( present( "deleted" ) ) {
        return new Selector( Selector::Flags, Selector::Contains, "\\deleted" );
    }
    else if ( present( "flagged" ) ) {
        return new Selector( Selector::Flags, Selector::Contains, "\\flagged" );
    }
    else if ( present( "new" ) ) {
        Selector * s = new Selector( Selector::And );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\recent" ) );
        Selector * n = new Selector( Selector::Not );
        s->add( n );
        n->add( new Selector( Selector::Flags, Selector::Contains, "\\seen" ) );
        return s;
    }
    else if ( present( "old" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\recent" ) );
        return s;
    }
    else if ( present( "recent" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\recent" ) );
        return s;
    }
    else if ( present( "seen" ) ) {
        return new Selector( Selector::Flags, Selector::Contains, "\\seen" );
    }
    else if ( present( "unanswered" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add(new Selector( Selector::Flags, Selector::Contains, "\\answered" ) );
        return s;
    }
    else if ( present( "undeleted" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\deleted" ) );
        return s;
    }
    else if ( present( "unflagged" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\flagged" ) );
        return s;
    }
    else if ( present( "unseen" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\seen" ) );
        return s;
    }
    else if ( present( "draft" ) ) {
        return new Selector( Selector::Flags, Selector::Contains, "\\draft" );
    }
    else if ( present( "undraft" ) ) {
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, "\\draft" ) );
        return s;
    }
    else if ( present( "on" ) ) {
        space();
        return new Selector( Selector::InternalDate, Selector::OnDate, date() );
    }
    else if ( present( "before" ) ) {
        space();
        return new Selector( Selector::InternalDate, Selector::BeforeDate, date() );
    }
    else if ( present( "since" ) ) {
        space();
        return new Selector( Selector::InternalDate, Selector::SinceDate, date() );
    }
    else if ( present( "sentbefore" ) ) {
        space();
        return new Selector( Selector::Sent, Selector::BeforeDate, date() );
    }
    else if ( present( "senton" ) ) {
        space();
        return new Selector( Selector::Sent, Selector::OnDate, date() );
    }
    else if ( present( "sentsince" ) ) {
        space();
        return new Selector( Selector::Sent, Selector::SinceDate, date() );
    }
    else if ( present( "from" ) ) {
        space();
        return new Selector( Selector::Header, Selector::Contains,
                             "from", ustring( AString ) );
    }
    else if ( present( "to" ) ) {
        space();
        return new Selector( Selector::Header, Selector::Contains,
                             "to", ustring( AString ) );
    }
    else if ( present( "cc" ) ) {
        space();
        return new Selector( Selector::Header, Selector::Contains,
                             "cc", ustring( AString ) );
    }
    else if ( present( "bcc" ) ) {
        space();
        return new Selector( Selector::Header, Selector::Contains,
                             "bcc", ustring( AString ) );
    }
    else if ( present( "subject" ) ) {
        space();
        return new Selector( Selector::Header, Selector::Contains,
                             "subject", ustring( AString ) );
    }
    else if ( present( "body" ) ) {
        space();
        return new Selector( Selector::Body, Selector::Contains,
                             ustring( AString ) );
    }
    else if ( present( "text" ) ) {
        space();
        UString a = ustring( AString );
        Selector * o = new Selector( Selector::Or );
        o->add( new Selector( Selector::Body, Selector::Contains, a ) );
        // field name is null for any-field searches
        o->add( new Selector( Selector::Header, Selector::Contains, 0, a ) );
        return o;
    }
    else if ( present( "keyword" ) ) {
        space();
        return new Selector( Selector::Flags, Selector::Contains,
                             atom().lower() );
    }
    else if ( present( "unkeyword" ) ) {
        space();
        Selector * s = new Selector( Selector::Not );
        s->add( new Selector( Selector::Flags, Selector::Contains, atom() ) );
        return s;
    }
    else if ( present( "header" ) ) {
        space();
        String s1 = astring();
        space();
        UString s2 = ustring( AString );
        return new Selector( Selector::Header, Selector::Contains, s1, s2 );
    }
    else if ( present( "uid" ) ) {
        space();
        return new Selector( set( false ) );
    }
    else if ( present( "or" ) ) {
        space();
        Selector * s = new Selector( Selector::Or );
        s->add( parseKey() );
        space();
        s->add( parseKey() );
        return s;
    }
    else if ( present( "not" ) ) {
        space();
        Selector * s = new Selector( Selector::Not );
        s->add( parseKey() );
        return s;
    }
    else if ( present( "larger" ) ) {
        space();
        return new Selector( Selector::Rfc822Size, Selector::Larger,
                             number() );
    }
    else if ( present( "smaller" ) ) {
        space();
        return new Selector( Selector::Rfc822Size, Selector::Smaller,
                             number() );
    }
    else if ( present( "annotation" ) ) {
        space();
        String a = parser()->listMailbox();
        if ( !parser()->ok() )
            error( Bad, parser()->error() );
        space();
        String b = atom();
        space();
        UString c = ustring( NString );

        uint i = 0;
        while ( ::legalAnnotationAttributes[i] &&
                b != ::legalAnnotationAttributes[i] )
            i++;
        if ( !::legalAnnotationAttributes[i] )
            error( Bad, "Unknown annotation attribute: " + b );

        return new Selector( Selector::Annotation, Selector::Contains,
                             a, b, c );
    }
    else if ( present( "modseq" ) ) {
        space();
        if ( nextChar() == '"' ) {
            // we don't store per-flag or per-annotation modseqs,
            // so RFC 4551 3.4 says we MUST ignore these
            (void)quoted(); // flag or annotation name
            space();
            (void)letters( 3, 6 ); // priv/shared/all
            space();
        }
        return new Selector( Selector::Modseq, Selector::Larger,
                             number() );
    }
    else if ( present( "older" ) ) {
        space();
        return new Selector( Selector::Age, Selector::Larger, nzNumber() );
    }
    else if ( present( "younger" ) ) {
        space();
        return new Selector( Selector::Age, Selector::Smaller, nzNumber() );
    }

    error( Bad, "expected search key, saw: " + following() );
    return new Selector;
}


void Search::execute()
{
    if ( state() != Executing )
        return;

    ImapSession * s = imap()->session();

    if ( !d->query ) {
        if ( d->root->needSession() && !s->initialised() ) {
            s->refresh( this );
            return;
        }
        considerCache();
        if ( d->done ) {
            sendResponse();
            finish();
            return;
        }

        d->query = d->root->query( imap()->user(), s->mailbox(), s, this );
        d->query->execute();
    }

    if ( !d->query->done() )
        return;

    if ( d->query->failed() ) {
        error( No, "Database error: " + d->query->error() );
        return;
    }

    bool firstRow = true;
    Row * r;
    while ( (r=d->query->nextRow()) != 0 ) {
        d->matches.add( r->getInt( "uid" ) );
        if ( d->returnModseq ) {
            int64 ms = r->getBigint( "modseq" );
            if ( firstRow )
                d->firstmodseq = ms;
            d->lastmodseq = ms;
            firstRow = false;
            if ( ms > d->highestmodseq )
                d->highestmodseq = ms;
        }
    }

    sendResponse();
    finish();
}


/*! Considers whether this search can and should be solved using this
    cache, and if so, finds all the matches.
*/

void Search::considerCache()
{
    if ( d->returnModseq )
        return;
    ImapSession * s = imap()->session();
    bool needDb = false;
    if ( d->root->field() == Selector::Uid &&
         d->root->action() == Selector::Contains ) {
        d->matches = s->messages().intersection( d->root->messageSet() );
        log( "UID-only search matched " +
             fn( d->matches.count() ) + " messages",
             Log::Debug );
    }
    else {
        uint max = s->count();
         // don't consider more than 300 messages - pg does it better
        if ( max > 300 )
            needDb = true;
        uint c = 0;
        while ( c < max && !needDb ) {
            c++;
            uint uid = s->uid( c );
            switch ( d->root->match( s, uid ) ) {
            case Selector::Yes:
                d->matches.add( uid );
                break;
            case Selector::No:
                break;
            case Selector::Punt:
                log( "Search must go to database: message " + fn( uid ) +
                     " could not be tested in RAM",
                     Log::Debug );
                needDb = true;
                d->matches.clear();
                break;
            }
            log( "Search considered " + fn( c ) + " of " + fn( max ) +
                 " messages using cache", Log::Debug );
        }
    }
    if ( !needDb )
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
    uint day = result.number( 0 );
    if ( result.length() < 2 )
        result = "0" + result;
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
    uint year = digits( 4, 4 ).number( 0 );
    if ( year < 1500 )
        error( Bad, "Years before 1500 not supported" );
    result.append( String::fromNumber( year ) );
    if ( q ) {
        if ( nextChar() != '"' )
            error( Bad, "Expected \", saw " + following() );
        else
            step();
    }
    Date tmp;
    tmp.setDate( year, month, day, 0, 0, 0, 0 );
    if ( !tmp.valid() )
        error( Bad, "Invalid date: " + result );
    return result;
}


/*! Reads an argument of type \a stringType (which may be AString,
    NString, or PlainString) and returns it as unicode, using the
    charset specified in the CHARSET argument to SEARCH.
*/

UString Search::ustring( Command::QuoteMode stringType )
{
    if ( !d->codec )
        d->codec = new AsciiCodec;

    String raw;
    switch( stringType )
    {
    case AString:
        raw = astring();
        break;
    case NString:
        raw = nstring();
        break;
    case PlainString:
        raw = string();
        break;
    }
    UString canon = d->codec->toUnicode( raw );
    if ( !d->codec->valid() )
        error( Bad,
               "astring not valid under encoding " + d->codec->name() +
               ": " + raw );
    return canon;
}


/*! This helper function is called by the parser to set the CHARSET for
    this search to \a s.
*/

void Search::setCharset( const String &s )
{
    d->charset = s;
    d->codec = Codec::byName( d->charset );
    if ( d->codec )
        return;

    String r = "[BADCHARSET";
    StringList::Iterator i( Codec::allCodecNames() );
    while ( i ) {
        r.append( " " );
        r.append( imapQuoted( *i, AString ) );
        ++i;
    }
    r.append( "] Unknown character encoding: " );
    r.append( d->charset.simplified() );

    error( No, r );
}


/*! Returns the root Selector constructed while parsing this Search
    command.
*/

Selector * Search::selector() const
{
    return d->root;
}


/*! This reimplementation of Command::set() simplifies the set by
    including messages that don't exist. \a parseMsns is as for
    Command::set().
*/

MessageSet Search::set( bool parseMsns )
{
    MessageSet s( Command::set( parseMsns ) );
    return s;
}


/*! Sends the SEARCH response.
*/

void Search::sendSearchResponse()
{
    ImapSession * s = imap()->session();
    String result( "SEARCH" );
    uint i = 1;
    uint max = d->matches.count();
    while ( i <= max ) {
        uint uid = d->matches.value( i );
        i++;
        if ( !d->uid )
            uid = s->msn( uid ); // ick
        if ( uid ) {
            result.append( " " );
            result.append( fn( uid ) );
        }
    }
    if ( d->returnModseq ) {
        result.append( " (modseq " );
        result.append( fn( d->highestmodseq ) );
        result.append( ")" );
    }
    respond( result );
}


static uint max( uint a, uint b )
{
    if ( a > b )
        return a;
    return b;
}


/*! Sends the ESEARCH response.
*/

void Search::sendEsearchResponse()
{
    ImapSession * s = imap()->session();
    String result = "ESEARCH (tag " + tag().quoted() + ")";
    if ( d->uid )
        result.append( " uid" );
    if ( d->returnCount ) {
        result.append( " count " );
        result.append( fn( d->matches.count() ) );
    }
    if ( d->returnMin && !d->matches.isEmpty() ) {
        result.append( " min " );
        uint uid = d->matches.value( 1 );
        if ( !d->uid )
            uid = s->msn( uid ); // ick
        result.append( fn( uid ) );
    }
    if ( d->returnMax && !d->matches.isEmpty() ) {
        result.append( " max " );
        uint uid = d->matches.value( d->matches.count() );
        if ( !d->uid )
            uid = s->msn( uid ); // ick
        result.append( fn( uid ) );
    }
    if ( d->returnAll && !d->matches.isEmpty() ) {
        result.append( " all " );
        if ( d->uid ) {
            result.append( d->matches.set() );
        }
        else {
            MessageSet msns;
            uint i = 1;
            uint max = d->matches.count();
            while ( i <= max ) {
                msns.add( s->msn( d->matches.value( i ) ) );
                i++;
            }
            result.append( msns.set() );
        }
    }
    if ( d->returnModseq && !d->matches.isEmpty() ) {
        result.append( " modseq " );
        if ( d->returnAll || d->returnCount )
            result.append( fn( d->highestmodseq ) );
        else if ( d->returnMin && d->returnMax )
            result.append( fn( max( d->firstmodseq, d->lastmodseq ) ) );
        else if ( d->returnMin )
            result.append( fn( d->firstmodseq ) );
        else if ( d->returnMax )
            result.append( fn( d->lastmodseq ) );
        else
            result.append( "1" ); // should not happen
    }
    respond( result );
}


/*! Calls either sendSearchResponse or sendEsearchResponse(),
    whichever is appropriate.
*/

void Search::sendResponse()
{
    if ( d->returnAll ||
         d->returnMax ||
         d->returnMin ||
         d->returnCount )
        sendEsearchResponse();
    else
        sendSearchResponse();
}
