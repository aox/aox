#include "fetch.h"

#include "set.h"

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
        List<String> fields;
        bool partial;
        uint offset;
        uint length;
    };

    Set set;
    bool peek;
    // we want to ask for...
    List<Section> sections;
    bool uid;
    bool flags;
    bool envelope;
    bool body;
    bool bodystructure;
    bool internaldate;
    bool rfc822size;
    // and the sections imply that we
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
}


/*! \reimp */

void Fetch::parse()
{
    space();
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
    end();
}


/*! \reimp */

void Fetch::execute()
{
    setState( Finished );
}


/*! This helper is responsible for parsing a single attriute from the
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
        // ###
    }
    else if ( keyword == "rfc822.header" ) {
        // ###
    }
    else if ( keyword == "rfc822.size" ) {
        d->rfc822size = true;
    }
    else if ( keyword == "rfc822.text" ) {
        // ###
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
  characters, all of which must be a letter or dot. Two consecutive
  dots aren't allowed.
*/

String Fetch::dotLetters( uint min, uint max )
{
    String r = letters( 1, max );
    while ( r.length() + 1 < max && nextChar() == '.' ) {
        step();
        r.append( "." );
        r.append( letters( 1, max - r.length() ) );
    }
    return r;
}


/*! Parses a bodypart description - the bit following "body[" in an
    attribute. The cursor must be after '[' on entry, and is left
    after the trailing ']'.
*/

void Fetch::parseBody()
{
    step();

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
        String tmp = dotLetters( 4, 17 ).lower();
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


static class FetchTest: public Test {
public:
    FetchTest(): Test( 610 ) {}
    void test() {
        setContext( "Testing Fetch" );
        
    }
} fetchTest;

