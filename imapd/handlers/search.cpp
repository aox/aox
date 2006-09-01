// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "search.h"

#include "imapsession.h"
#include "annotation.h"
#include "messageset.h"
#include "listext.h"
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
          query( 0 )
    {}

    bool uid;
    bool done;

    String charset;
    Codec * codec;

    Selector * root;
    List< Selector > selectors;

    Query * query;
    MessageSet matches;
};


/*! \class Search search.h
    Finds messages matching some criteria (RFC 3501 section 6.4.4)

    The entirety of the basic syntax is handled, as well as parts of
    CONDSTORE (RFC 4551). SEARCHM probably will need to be implemented
    as a subclass of Search. How about ESEARCH?

    Searches are first run against the RAM cache, rudimentarily. If
    the comparison is difficult, expensive or unsuccessful, it gives
    up and uses the database.
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
    d->selectors.append( d->root );
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

    d->root->simplify();
    log( "Search for " + d->root->debugString() );
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
        push( Selector::And );
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
        add( new Selector( set( true ) ) );
        if ( !d->uid )
            setGroup( 0 );
    }
    else {
        // first comes a keyword. they all are letters only, so:
        String keyword = letters( 2, 15 ).lower();
        if ( keyword == "all" ) {
            add( new Selector( Selector::NoField, Selector::All ) );
        }
        else if ( keyword == "answered" ) {
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\answered" ) );
        }
        else if ( keyword == "deleted" ) {
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\deleted" ) );
        }
        else if ( keyword == "flagged" ) {
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\flagged" ) );
        }
        else if ( keyword == "new" ) {
            push( Selector::And );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\recent" ) );
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\seen" ) );
            pop();
            pop();
        }
        else if ( keyword == "old" ) {
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\recent" ) );
            pop();
        }
        else if ( keyword == "recent" ) {
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\recent" ) );
        }
        else if ( keyword == "seen" ) {
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\seen" ) );
        }
        else if ( keyword == "unanswered" ) {
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\answered" ) );
            pop();
        }
        else if ( keyword == "undeleted" ) {
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\deleted" ) );
            pop();
        }
        else if ( keyword == "unflagged" ) {
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\flagged" ) );
            pop();
        }
        else if ( keyword == "unseen" ) {
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\seen" ) );
            pop();
        }
        else if ( keyword == "draft" ) {
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\draft" ) );
        }
        else if ( keyword == "undraft" ) {
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains,
                               "\\draft" ) );
            pop();
        }
        else if ( keyword == "on" ) {
            space();
            add( new Selector( Selector::InternalDate, Selector::OnDate,
                               date() ) );
        }
        else if ( keyword == "before" ) {
            add( new Selector( Selector::InternalDate, Selector::BeforeDate,
                               date() ) );
        }
        else if ( keyword == "since" ) {
            space();
            add( new Selector( Selector::InternalDate, Selector::SinceDate,
                               date() ) );
        }
        else if ( keyword == "sentbefore" ) {
            space();
            add( new Selector( Selector::Sent, Selector::BeforeDate,
                               date() ) );
        }
        else if ( keyword == "senton" ) {
            space();
            add( new Selector( Selector::Sent, Selector::OnDate, date() ) );
        }
        else if ( keyword == "sentsince" ) {
            space();
            add( new Selector( Selector::Sent, Selector::SinceDate, date() ) );
        }
        else if ( keyword == "from" ) {
            space();
            add( new Selector( Selector::Header, Selector::Contains,
                               "from", ustring( AString ) ) );
        }
        else if ( keyword == "to" ) {
            space();
            add( new Selector( Selector::Header, Selector::Contains,
                               "to", ustring( AString ) ) );
        }
        else if ( keyword == "cc" ) {
            space();
            add( new Selector( Selector::Header, Selector::Contains,
                               "cc", ustring( AString ) ) );
        }
        else if ( keyword == "bcc" ) {
            space();
            add( new Selector( Selector::Header, Selector::Contains,
                               "bcc", ustring( AString ) ) );
        }
        else if ( keyword == "subject" ) {
            space();
            add( new Selector( Selector::Header, Selector::Contains,
                               "subject", ustring( AString ) ) );
        }
        else if ( keyword == "body" ) {
            space();
            add( new Selector( Selector::Body, Selector::Contains,
                               ustring( AString ) ) );
        }
        else if ( keyword == "text" ) {
            space();
            UString a = ustring( AString );
            push( Selector::Or );
            add( new Selector( Selector::Body, Selector::Contains, a ) );
            // field name is null for any-field searches
            add( new Selector( Selector::Header, Selector::Contains, 0, a ) );
            pop();
        }
        else if ( keyword == "keyword" ) {
            space();
            add( new Selector( Selector::Flags, Selector::Contains,
                               atom().lower() ) );
        }
        else if ( keyword == "unkeyword" ) {
            space();
            push( Selector::Not );
            add( new Selector( Selector::Flags, Selector::Contains, atom() ) );
            pop();
        }
        else if ( keyword == "header" ) {
            space();
            String s1 = astring();
            space();
            UString s2 = ustring( AString );
            add( new Selector( Selector::Header, Selector::Contains, s1, s2 ) );
        }
        else if ( keyword == "uid" ) {
            space();
            add( new Selector( set( false ) ) );
        }
        else if ( keyword == "or" ) {
            space();
            push( Selector::Or );
            parseKey();
            space();
            parseKey();
            pop();
        }
        else if ( keyword == "not" ) {
            space();
            push( Selector::Not );
            parseKey();
            pop();
        }
        else if ( keyword == "larger" ) {
            space();
            add( new Selector( Selector::Rfc822Size, Selector::Larger,
                               number() ) );
        }
        else if ( keyword == "smaller" ) {
            space();
            add( new Selector( Selector::Rfc822Size, Selector::Smaller,
                               number() ) );
        }
        else if ( keyword == "annotation" ) {
            space();
            String a = listMailbox();
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

            add( new Selector( Selector::Annotation, Selector::Contains,
                               a, b, c ) );
        }
        else if ( keyword == "modseq" ) {
            space();
            if ( nextChar() == '"' ) {
                // we don't store per-flag or per-annotation modseqs,
                // so RFC 4551 3.4 says we MUST ignore these
                (void)quoted(); // flag or annotation name
                space();
                (void)letters( 3, 6 ); // priv/shared/all
                space();
            }
            add( new Selector( Selector::Modseq, Selector::Larger,
                               number() ) );
        }
        else if ( alsoCharset && keyword == "charset" ) {
            space();
            setCharset( astring() );
        }
        else {
            error( Bad, "unknown search key: " + keyword );
        }
    }

    alsoCharset = false;
}


void Search::execute()
{
    ImapSession * s = imap()->session();

    if ( !d->query ) {
        if ( d->root->needSession() && !s->initialised() ) {
            s->refresh( this );
            return;
        }
        considerCache();
        if ( d->done ) {
            sendSearchResponse();
            finish();
            return;
        }

        Mailbox * m = s->mailbox();
        if ( m->view() )
            m = m->source();

        d->query =
            d->root->query( imap()->user(), m, s, this );

        m = s->mailbox();
        if ( m->view() ) {
            uint source = d->root->placeHolder();
            uint view = d->root->placeHolder();
            String s( "select uid from view_messages where source=$" +
                      fn( source ) + " and view=$" + fn( view ) +
                      " and suid in (" + d->query->string() + ")"
                      " order by uid" );
            d->query->bind( source, m->source()->id() );
            d->query->bind( view, m->id() );
            d->query->setString( s );
        }

        d->query->execute();
    }

    if ( !d->query->done() )
        return;

    if ( d->query->failed() ) {
        error( No, "Database error: " + d->query->error() );
        return;
    }

    Row * r;
    String result( "SEARCH" );
    while ( (r=d->query->nextRow()) != 0 )
        d->matches.add( r->getInt( "uid" ) );

    sendSearchResponse();
    finish();
}


/*! Considers whether this search can and should be solved using this
    cache, and if so, finds all the matches.
*/

void Search::considerCache()
{
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


/*! Appends a new Selector of type \a a to the list of selectors. */

void Search::push( Selector::Action a )
{
    Selector * s = new Selector( a );
    add( s );
    d->selectors.append( s );
}


/*! Adds the new Selector \a s to the boolean Selector currently being
    constructed.
*/

void Search::add( Selector * s )
{
    d->selectors.last()->add( s );
}


/*! Removes the current And/Or/Not Selector from the list, marking the
    end of its creation.
*/

void Search::pop()
{
    d->selectors.pop();
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
    if ( d->codec == 0 )
        error( No, "[BADCHARSET] Unknown character encoding: " +
               d->charset );
}


/*! Returns the root Selector constructed while parsing this Search
    command.
*/

Selector * Search::selector() const
{
    return d->root;
}


/*! This reimplementation of Command::set() simplifies the set by
    including messages that don't exist, and returns UIDs in the
    underlying mailbox rather than a view. \a parseMsns is as for
    Command::set().
*/

MessageSet Search::set( bool parseMsns )
{
    MessageSet s( Command::set( parseMsns ) );
    Mailbox * m = imap()->session()->mailbox();
    if ( m->view() )
        return m->sourceUids( s );
    
    s.addGapsFrom( imap()->session()->messages() );
    return s;
}


/*! Sends the SEARCH response, or ESEARCH, or whatever is called
    for.
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
    respond( result );
}
