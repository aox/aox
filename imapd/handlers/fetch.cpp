#include "fetch.h"

#include "set.h"
#include "stringlist.h"
#include "arena.h"
#include "scope.h"
#include "imap.h"

#include "test.h"

// fetch           = "FETCH" SP set SP ("ALL" / "FULL" / "FAST" / fetch-att /
//                   "(" fetch-att *(SP fetch-att) ")")
// fetch-att       = "ENVELOPE" / "FLAGS" / "INTERNALDATE" /
//                   "RFC822" [".HEADER" / ".SIZE" / ".TEXT"] /
//                   "BODY" ["STRUCTURE"] / "UID" /
//                   "BODY" [".PEEK"] section ["<" number "." nz-number ">"]
// section         = "[" [section-spec] "]"
// section-spec    = section-msgtext / (section-part ["." section-text])
// section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP header-list /
//                   "TEXT"
// section-part    = nz-number *("." nz-number)
// section-text    = section-msgtext / "MIME"
// header-list     = "(" header-fld-name *(SP header-fld-name) ")"
// header-fld-name = astring


class FetchData {
public:
    FetchData()
        : peek( true ),
          uid( false ), flags( false ), envelope( false ), body( false ),
          bodystructure( false ), internaldate( false ), rfc822size( false ),
          needHeader( false ), needBody( false )
    {}

    class Section {
    public:
        Section()
            : partial( false ), offset( 0 ), length( UINT_MAX ) {}

        String id;
        StringList fields;
        bool partial;
        uint offset;
        uint length;
    };

    Set set;
    bool peek;
    // we want to ask for...
    bool uid;
    bool flags;
    bool envelope;
    bool body;
    bool bodystructure;
    bool internaldate;
    bool rfc822size;
    List<Section> sections;
    // and the sections imply that we...
    bool needHeader;
    bool needBody;
};


/*! \class Fetch fetch.h
    Returns message data (RFC 3501, section 6.4.5).

    Our implementation is slightly more permissive than the RFC; it
    permits FETCH BODY[MIME] and perhaps more.

    The flag update is slavishly followed, including that for
    read-only mailboxes, flags aren't changed. (Well, that's how it
    will be, anyway.)
*/


/*! Creates a new handler for FETCH if \a u is false, or for UID FETCH
    if \a u is true.
*/

Fetch::Fetch( bool u )
    : Command(), uid( u ), d( new FetchData )
{
    d->uid = u;
}


/*! \reimp */

void Fetch::parse()
{
    d->set = set( !uid );
    space();
    if ( nextChar() == '(' ) {
        // "(" fetch-att *(SP fetch-att) ")")
        step();
        parseAttribute( false );
        while( nextChar() == ' ' ) {
            step();
            parseAttribute( false );
        }
        require( ")" );
    }
    else {
        // single fetch-att, or the macros
        parseAttribute( true );
    }
    if ( d->envelope || d->body || d->bodystructure )
        d->needHeader = true;
    if ( d->body || d->bodystructure )
        d->needBody = true;
    end();
}


/*! \reimp */

void Fetch::execute()
{
    if ( d->set.isEmpty() ) {
        setState( Finished );
        return;
    }


}


/*! This helper is responsible for parsing a single attribute from the
    fetch arguments. If \a alsoMacro is true, this function parses a
    macro as well as a single attribute.
*/

void Fetch::parseAttribute( bool alsoMacro )
{
    String keyword = dotLetters( 3, 13 ).lower(); // UID/ALL, RFC822.HEADER
    if ( alsoMacro && keyword == "all" ) {
        // equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE)
        d->flags = true;
        d->envelope = true;
        d->internaldate = true;
        d->rfc822size = true;
    }
    else if ( alsoMacro && keyword == "full" ) {
        // equivalent to: (FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODY)
        d->flags = true;
        d->envelope = true;
        d->body = true;
        d->internaldate = true;
        d->rfc822size = true;
    }
    else if ( alsoMacro && keyword == "fast" ) {
        // equivalent to: (FLAGS INTERNALDATE RFC822.SIZE)
        d->flags = true;
        d->internaldate = true;
        d->rfc822size = true;
    }
    else if ( keyword == "envelope" ) {
        d->envelope = true;
    }
    else if ( keyword == "flags" ) {
        d->flags = true;
    }
    else if ( keyword == "internaldate" ) {
        d->internaldate = true;
    }
    else if ( keyword == "rfc822" ) {
        d->peek = false;
        d->needHeader = true;
        d->needBody = true;
        FetchData::Section * s = new FetchData::Section;
        s->id = keyword;
        d->sections.append( s );
    }
    else if ( keyword == "rfc822.header" ) {
        d->needHeader = true;
        FetchData::Section * s = new FetchData::Section;
        s->id = keyword;
        d->sections.append( s );
    }
    else if ( keyword == "rfc822.size" ) {
        d->rfc822size = true;
    }
    else if ( keyword == "rfc822.text" ) {
        d->peek = false;
        d->needBody = true;
        FetchData::Section * s = new FetchData::Section;
        s->id = keyword;
        d->sections.append( s );
    }
    else if ( keyword == "body.peek" && nextChar() == '[' ) {
        step();
        parseBody();
    }
    else if ( keyword == "body" ) {
        if ( nextChar() == '[' ) {
            d->peek = false;
            step();
            parseBody();
        }
        else {
            d->body = true;
            // poor man's bodystructure
        }
    }
    else if ( keyword == "bodystructure" ) {
        d->bodystructure = true;
        // like body, but with bells and whistles
    }
    else if ( keyword == "uid" ) {
        d->uid = true;
    }
    else {
        error( Bad, "expected fetch attribute, saw word " + keyword );
    }

// fetch           = "FETCH" SP set SP ("ALL" / "FULL" / "FAST" / fetch-att /
//                   "(" fetch-att *(SP fetch-att) ")")
// fetch-att       = "ENVELOPE" / "FLAGS" / "INTERNALDATE" /
//                   "RFC822" [".HEADER" / ".SIZE" / ".TEXT"] /
//                   "BODY" ["STRUCTURE"] / "UID" /
//                   "BODY" [".PEEK"] section ["<" number "." nz-number ">"]

}


/*! This utility function fetches at least \a min, at most \a max
    characters, all of which must be a letter, a digit or a dot.
    Consecutive dots ARE allowed.
*/

String Fetch::dotLetters( uint min, uint max )
{
    String r;
    uint i = 0;
    char c = nextChar();
    while ( i < max &&
            ( ( c >= 'A' && c <= 'Z' ) ||
              ( c >= 'a' && c <= 'z' ) ||
              ( c >= '0' && c <= '9' ) ||
              ( c == '.' ) ) ) {
        step();
        r.append( c );
        c = nextChar();
        i++;
    }
    if ( i < min )
        error( Bad, "Expected at least " + String::fromNumber( min-i ) +
               " more letters/digits/dots, saw " + following() );
    return r;
}


/*! Parses a bodypart description - the bit following "body[" in an
    attribute. The cursor must be after '[' on entry, and is left
    after the trailing ']'.
*/

void Fetch::parseBody()
{
    //section-spec    = section-msgtext / (section-part ["." section-text])
    //section-msgtext = "HEADER" /
    //                  "HEADER.FIELDS" [".NOT"] SP header-list /
    //                  "TEXT"
    //section-part    = nz-number *("." nz-number)
    //section-text    = section-msgtext / "MIME"
    FetchData::Section * s = new FetchData::Section;

    bool sectionValid = true;
    while ( sectionValid && nextChar() >= '0' && nextChar() <= '9' ) {
        s->id.append( String::fromNumber( nzNumber() ) );
        if ( nextChar() == '.' ) {
            s->id.append( "." );
            step();
        }
        else {
            sectionValid = false;
        }
    }

    if ( sectionValid ) {
        String tmp = dotLetters( 0, 17 ).lower();
        s->id.append( tmp );
        if ( tmp == "text" || tmp == "mime" || tmp == "header" ) {
            if ( tmp == s->id )
                d->needHeader = true;
            else
                d->needBody = true;
        }
        else if ( tmp == "header.fields" || tmp == "header.fields.not" ) {
            space();
            require( "(" );
            s->fields.append( new String( astring().headerCased() ) );
            while ( nextChar() == ' ' ) {
                space();
                s->fields.append( new String( astring().headerCased() ) );
            }
            require( ")" );
        }
        else if ( s->id.isEmpty() ) {
            // it's okay
        }
        else {
            error( Bad, "expected text, header, header.fields etc, "
                   "not " + tmp + following() );
        }
    }

    if ( nextChar() == '<' ) {
        s->partial = true;
        step();
        s->offset = number();
        require( "." );
        s->length = nzNumber();
        require( ">" );
    }

    require( "]" );

    d->sections.append( s );
}



/*! Returns an SQL query string to fetch

*/

String Fetch::query() const
{
    if ( !d->uid &&
         !d->flags &&
         !d->envelope &&
         !d->body &&
         !d->bodystructure &&
         !d->internaldate &&
         !d->rfc822size &&
         !d->needHeader &&
         !d->needBody )
        return "";


    StringList bools;
    if ( d->flags )
        bools.append( "flags" );
    if ( d->internaldate )
        bools.append( "internaldate" );
    if ( d->rfc822size )
        bools.append( "rfc822size" );
    if ( d->uid )
        bools.append( "uid" );

    String q = "select (" + bools.join( "," ) + ") from messages where " +
               d->set.where();
    return q;
}


static struct {
    const char * args;
    const char * query;
} fetches[] = {
    { "1,2,3 flags",
      "select (flags,uid) from messages where uid<4" },
    { "2,3 flags",
      "select (flags,uid) from messages where uid>=2 and uid<4" },
    { "2,3 (flags)",
      "select (flags,uid) from messages where uid>=2 and uid<4" },
    { "2,3 (flags uid)",
      "select (flags,uid) from messages where uid>=2 and uid<4" },
    { "1 uid",
      "select (uid) from messages where uid=1" },
    { "1 all",
      "select (flags,internaldate,rfc822size,uid) from messages where uid=1" },
    { "1 fast",
      "select (flags,internaldate,rfc822size,uid) from messages where uid=1" },
    { "1 full",
      "select (flags,internaldate,rfc822size,uid) from messages where uid=1" },
    { "1 (uid rfc822)",
      "select (uid) from messages where uid=1" },
    { "1 (uid rfc822.size)",
      "select (rfc822size,uid) from messages where uid=1" },
    { "1 (uid rfc822.text)",
      "select (uid) from messages where uid=1" },
    { "1 (uid rfc822.header)",
      "select (uid) from messages where uid=1" },
    { "1 (uid body.peek[])",
      "select (uid) from messages where uid=1" },
    { "1 (uid body.peek[1])",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[mime]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1.mime]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1.2.mime]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[header]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[text]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1.header]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1.text]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1.123456789.header]",
      "select (uid) from messages where uid=1" },
    { "1 body.peek[1.23456789.text]",
      "select (uid) from messages where uid=1" },
    { 0, 0 }
};


static class FetchTest: public Test {
public:
    FetchTest(): Test( 610 ) {}
    void test() {
        setContext( "Testing Fetch" );

        IMAP imap( -1 );
        imap.setState( IMAP::Selected );
        String tag = "a";
        uint i = 0;
        while ( fetches[i].args != 0 ) {
            Arena a;
            Scope s( &a );
            StringList l;
            l.append( fetches[i].args );
            Fetch * f
                = (Fetch *)Command::create( &imap, "uid fetch", tag, &l, &a );
            if ( f )
                f->parse();
            verify( "Fetch parsing broke",
                    !f, !f->ok(), f->query() != fetches[i].query );
            i++;
        }
    }
} fetchTest;
