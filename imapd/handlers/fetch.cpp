// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fetch.h"

#include "messageset.h"
#include "stringlist.h"
#include "imapsession.h"
#include "address.h"
#include "message.h"
#include "arena.h"
#include "scope.h"
#include "imap.h"
#include "flag.h"
#include "date.h"

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

    MessageSet set;
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
    if ( d->envelope || d->body || d->bodystructure )
        d->needHeader = true;
    if ( d->body || d->bodystructure )
        d->needBody = true;
    end();
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
        error( Bad, "Expected at least " + fn( min-i ) +
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
        s->id.append( fn( nzNumber() ) );
        if ( nextChar() == '.' ) {
            s->id.append( "." );
            step();
        }
        else {
            sectionValid = false;
        }
    }

    d->needHeader = true; // need that for the boundary, if nothing else
    d->needBody = true;

    if ( sectionValid ) {
        String tmp = dotLetters( 0, 17 ).lower();
        if ( tmp == "text" ) {
            if ( s->id.isEmpty() )
                d->needHeader = false;
        }
        else if ( tmp == "mime" || tmp == "header" ) {
            if ( s->id.isEmpty() )
                d->needBody = false;
        }
        else if ( tmp == "header.fields" || tmp == "header.fields.not" ) {
            if ( s->id.isEmpty() )
                d->needBody = false;
            space();
            require( "(" );
            s->fields.append( new String( astring().headerCased() ) );
            while ( nextChar() == ' ' ) {
                space();
                s->fields.append( new String( astring().headerCased() ) );
            }
            require( ")" );
        }
        else if ( tmp.isEmpty() && s->id.isEmpty() ) {
            // it's okay
        }
        else {
            error( Bad, "expected text, header, header.fields etc, "
                   "not " + tmp + following() );
        }
        s->id.append( tmp );
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


void Fetch::execute()
{
    ImapSession * s = imap()->session();
    uint i = 0;
    bool done = true;
    while ( i < d->set.count() ) {
        i++;
        uint uid = d->set.value( i );
        Message * m = s->message( uid );
        bool ok = false;
        if ( m ) {
            ok = true;
            if ( d->needHeader && !m->hasHeaders() ) {
                m->fetchHeaders( this );
                ok = false;
            }
            if ( d->needBody && !m->hasBodies() ) {
                m->fetchBodies( this );
                ok = false;
            }
            if ( d->flags && !m->hasExtraFlags() ) {
                m->fetchExtraFlags( this );
                ok = false;
            }
            if ( ok )
                respond( fetchResponse( m, uid, s->msn( uid ) ),
                         Untagged );
            else
                done = false;
        }
    }
    if ( done )
        finish();
}


/*! Emits a single FETCH response for the messae \a m, which is
    trusted to have UID \a uid and MSN \a msn.

    The message must have all necessary content.
*/

String Fetch::fetchResponse( Message * m, uint uid, uint msn )
{
    StringList l;
    if ( d->uid )
        l.append( "UID " + fn( uid ) );
    if ( d->rfc822size )
        l.append( "RFC822.SIZE " + fn( d->rfc822size ) );
    if ( d->flags )
        l.append( "FLAGS (" + flagList( m, uid ) + ")" );
    if ( d->internaldate )
        l.append( "INTERNALDATE " + internalDate( m ) );
    if ( d->envelope )
        l.append( "ENVELOPE " + envelope( m ) );
    if ( d->body )
        l.append( "BODY " + bodystructure( m, false ) );
    if ( d->bodystructure )
        l.append( "BODYSTRUCTURE " + bodystructure( m, true ) );

    // deal with the sections here

    String r = fn( msn ) + " FETCH (" + l.join( " " ) + ")";
    return r;
}


/*! Returns a string containing all the flags that are set for message
    \a m, which has UID \a uid.
*/

String Fetch::flagList( Message * m, uint uid )
{
    StringList r;

    if ( m->flag( Message::AnsweredFlag ) )
        r.append( "\\answered" );
    if ( m->flag( Message::DeletedFlag ) )
        r.append( "\\deleted" );
    if ( m->flag( Message::DraftFlag ) )
        r.append( "\\draft" );
    if ( m->flag( Message::FlaggedFlag ) )
        r.append( "\\flagged" );
    if ( m->flag( Message::SeenFlag ) )
        r.append( "\\seen" );

    if ( imap()->session()->isRecent( uid ) )
        r.append( "\\recent" );

    List<Flag> * f = m->extraFlags();
    if ( f && !f->isEmpty() ) {
        List<Flag>::Iterator it = f->first();
        while ( it ) {
            r.append( it->name() );
            ++it;
        }
    }

    return r.join( " " );
}


/*! Returns the internaldate of \a m in IMAP format. */

String Fetch::internalDate( Message * m )
{
    Date date;
    date.setUnixTime( m->internalDate() );
    return date.imap();
}


static String hf( Header * f, HeaderField::Type t )
{
    List<Address> * a = f->addresses( t );
    if ( !a || a->isEmpty() )
        return "NIL ";
    String r( "(" );
    List<Address>::Iterator it( a->first() );
    while ( it ) {
        r.append( "(" );
        r.append( Command::imapQuoted( it->name(), Command::NString ) );
        r.append( " NIL " );
        r.append( Command::imapQuoted( it->localpart(), Command::NString ) );
        r.append( " " );
        r.append( Command::imapQuoted( it->domain(), Command::NString ) );
        r.append( ")" );
        ++it;
    }
    r.append( ") " );
    return r;
}

/*! Returns the IMAP envelope for \a m. */

String Fetch::envelope( Message * m )
{
    Header * h = m->header();

    String r( "(" );

    Date * date = h->date();
    if ( date )
        r.append( imapQuoted( date->rfc822(), NString ) + " " );
    else
        r.append( "NIL " );

    r.append( imapQuoted( h->subject(), NString ) + " " );
    r.append( hf( h, HeaderField::From ) );
    r.append( hf( h, HeaderField::Sender ) );
    r.append( hf( h, HeaderField::ReplyTo ) );
    r.append( hf( h, HeaderField::To ) );
    r.append( hf( h, HeaderField::Cc ) );
    r.append( hf( h, HeaderField::Bcc ) );
    r.append( imapQuoted( h->inReplyTo(), NString ) + " " );
    r.append( imapQuoted( h->messageId(), NString ) + " " );

    r.append( ")" );
    return r;

    // envelope        = "(" env-date SP env-subject SP env-from SP
    //                   env-sender SP env-reply-to SP env-to SP env-cc SP
    //                   env-bcc SP env-in-reply-to SP env-message-id ")"
}


/*! Returns either the IMAP BODY or BODYSTRUCTURE production for \a
    m. If \a extended is true, BODYSTRUCTURE is returned. If it's
    false, BODY.
*/

String Fetch::bodystructure( Message * m, bool extended )
{
    Header * h = m->header();
    StringList l;

    // body            = "(" (body-type-1part / body-type-mpart) ")"

    ContentType * ct = h->contentType();

    if ( ct->type() == "multipart" ) {
        // body-type-mpart = 1*body SP media-subtype
        //                   [SP body-ext-mpart]
    }
    else {
        // body-type-1part=(body-type-basic / body-type-msg / body-type-text)
        // body-type-basic = media-basic SP body-fields
        //                     ; MESSAGE subtype MUST NOT be "RFC822"
        // body-type-msg   = media-message SP body-fields SP envelope
        //                   SP body SP body-fld-lines
        // body-type-text  = media-text SP body-fields SP body-fld-lines

        // media-basic, media-message and media-text are all the same:
        l.append( imapQuoted( ct->type() ) );
        l.append( imapQuoted( ct->subtype() ) );

        // body-fields = body-fld-param SP body-fld-id SP body-fld-desc SP
        //               body-fld-enc SP body-fld-octets

        // body-fld-param  = "(" string SP string *(SP string SP string) ")"
        //                    / nil
        StringList * params = ct->parameterList();
        if ( !params || params->isEmpty() ) {
            l.append( "NIL" );
        }
        else {
            StringList p;
            StringList::Iterator i( params->first() );
            while ( i ) {
                p.append( imapQuoted( *i ) );
                p.append( imapQuoted( ct->parameter( *i ) ) );
                ++i;
            }
            l.append( "(" + p.join( " " ) + ")" );
        }

        // body-fld-id     = nstring
        // body-fld-desc   = nstring
        l.append( imapQuoted( h->messageId( HeaderField::ContentId ) ) );
        l.append( imapQuoted( h->contentDescription() ) );

        // body-fld-enc    = (DQUOTE ("7BIT" / "8BIT" / "BINARY" / "BASE64"/
        //                   "QUOTED-PRINTABLE") DQUOTE) / string
        if ( h->contentTransferEncoding() ) {
            switch( h->contentTransferEncoding()->encoding() ) {
            case ContentTransferEncoding::Binary:
                l.append( "\"8BIT\"" ); // hm. is this entirely sound?
                break;
            case ContentTransferEncoding::Base64:
                l.append( "\"BASE64\"" );
                break;
            case ContentTransferEncoding::QuotedPrintable:
                l.append( "\"QUOTED-PRINTABLE\"" );
                break;
            }
        }
        else {
            l.append( "\"7BIT\"" );
        }

        BodyPart * bp = m->bodyPart( 1 );

        // body-fld-octets = number
        if ( bp )
            l.append( fn( bp->numBytes() ) );
        
        if ( !bp ) {
            // what to do? hard to know.
        }
        else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
            // body-type-msg   = media-message SP body-fields SP envelope
            //                   SP body SP body-fld-lines

            l.append( envelope( bp->rfc822() ) );
            l.append( bodystructure( bp->rfc822(), extended ) );
            l.append( fn( bp->numBytes() ) );
        }
        else if ( ct->type() == "text" ) {
            // body-type-text  = media-text SP body-fields SP body-fld-lines

            l.append( fn( bp->numLines() ) );
        }
    }

    return "(" + l.join( " " ) + ")";
}
