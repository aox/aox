#include "fetch.h"

#include "set.h"

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
        : seen( false ), 
          uid( false ), flags( false ), envelope( false ), body( false ),
          bodystructure( false ), internaldate( false ), rfc822size( false )
    {}

    Set set;
    bool seen;
    // we want to ask for...
    bool uid;
    bool flags;
    bool envelope;
    bool body;
    bool bodystructure;
    bool internaldate;
    bool rfc822size;
};


void Fetch::parse()
{
    d->uid = uid;
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
        if ( nextChar() != ')' )
            error( Bad, "closing paren missing, saw " + following() );
        step();
    }
    else {
        // single fetch-att, or the macros
        parseAttribute( true );
    }
    end();
}


void Fetch::execute()
{
    setState( Finished );
}


/*!

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
        d->seen = true;
    }
    else if ( keyword == "rfc822.header" ) {
    }
    else if ( keyword == "rfc822.size" ) {
        d->rfc822size = true;
    }
    else if ( keyword == "rfc822.text" ) {
    }
    else if ( keyword == "body.peek" ) {
        parseBody();
    }
    else if ( keyword == "body" ) {
        if ( nextChar() == '[' ) {
            parseBody();
            d->seen = true;
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


/*!

*/

String Fetch::dotLetters( uint min, uint max )
{
    String r = letters( 1, max );
    while ( r.length() + 1 < min && nextChar() == '.' ) {
        step();
        r.append( "." );
        r.append( letters( 1, max - r.length() ) );
    }
    return r;
}


/*!

*/

void Fetch::parseBody()
{
    if ( nextChar() != '[' )
        error( Bad, "Need [ following body/body.peek" );
    step();

    //section-spec    = section-msgtext / (section-part ["." section-text])
    //section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP header-list / "TEXT"
    //section-part    = nz-number *("." nz-number)
    //section-text    = section-msgtext / "MIME"
    bool dot = false;
    String section;
    while ( ( section.isEmpty() || dot ) && nextChar() <= '9' ) {
        if ( dot )
            section.append( "." );
        dot = false;
        section.append( String::fromNumber( nzNumber() ) );
        if ( nextChar() == '.' ) {
            dot = true;
            step();
        }
    }
    if ( section.isEmpty() || dot ) {
        String tmp = dotLetters( 4, 17 ).lower();
        if ( tmp == "text" ) {
        }
        else if ( tmp == "mime" ) {
        }
        else if ( tmp == "header" ) {
        }
        else if ( tmp == "header.fields" ||
                  tmp == "header.fields.not" ) {
            bool hfn = (tmp == "header.fields.not");
            hfn = hfn; // ### hack to kill warning
            space();
            if ( nextChar() != '(' )
                error( Bad, "Expected header field list" );
            step();
            List<String> fields;
            fields.append( new String( astring() ) );
            while ( nextChar() == ' ' ) {
                space();
                fields.append( new String( astring() ) );
            }
            if ( nextChar() != ')' )
                error( Bad, "Expected header field list" );
            step();
        }
        else {
            error( Bad, "expected text, header, header.fields etc, "
                   "not " + tmp );
        }
    }
    if ( nextChar() == '<' ) {
        step();
        uint n = number();
        n = n; // ### hack to kill warning
        if ( nextChar() != '.' )
            error( Bad, "Must have '.' in range specification, not " + 
                   following() );
        step();
        uint r = nzNumber();
        r = r; // ### hack to kill warning
        if ( nextChar() != '>' )
            error( Bad, "Must end range specification with '>', not " + 
                   following() );
        step();
    }
}
