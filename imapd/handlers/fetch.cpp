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
        : state( Fetch::Initial ), peek( true ),
          uid( false ), flags( false ), envelope( false ), body( false ),
          bodystructure( false ), internaldate( false ), rfc822size( false ),
          needHeader( false ), needBody( false )
    {}

    class Section {
    public:
        Section()
            : partial( false ), offset( 0 ), length( UINT_MAX ) {}

        String id;
        String part;
        StringList fields;
        bool partial;
        uint offset;
        uint length;
    };

    Fetch::State state;
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

    Our implementation is slightly more permissive than the RFC.

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
    FetchData::Section * s = new FetchData::Section;

    //section-spec    = section-msgtext / (section-part ["." section-text])
    //section-msgtext = "HEADER" /
    //                  "HEADER.FIELDS" [".NOT"] SP header-list /
    //                  "TEXT"
    //section-part    = nz-number *("." nz-number)
    //section-text    = section-msgtext / "MIME"

    // Parse a section-part.
    bool dot = false;
    if ( nextChar() >= '0' && nextChar() <= '9' ) {
        String part;
        part.append( fn( nzNumber() ) );
        while ( nextChar() == '.' ) {
            step();
            if ( nextChar() >= '0' && nextChar() <= '9' ) {
                part.append( "." );
                part.append( fn( nzNumber() ) );
                if ( nextChar() != '.' &&
                     nextChar() != ']' )
                    error( Bad, "" );
            }
            else {
                dot = true;
                break;
            }
        }
        s->part = part;
    }

    d->needHeader = true; // need that for the boundary, if nothing else
    d->needBody = true;

    // Parse any section-text.
    String item = dotLetters( 0, 17 ).lower();
    if ( item == "text" ) {
        if ( s->part.isEmpty() )
            d->needHeader = false;
    }
    else if ( item == "header" ) {
        if ( s->part.isEmpty() )
            d->needBody = false;
    }
    else if ( item == "header.fields" ||
              item == "header.fields.not" )
    {
        if ( s->part.isEmpty() )
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
    else if ( item == "mime" ) {
        if ( s->part.isEmpty() )
            error( Bad, "MIME requires a section-part." );
    }
    else if ( !item.isEmpty() || dot ) {
        error( Bad, "expected text, header, header.fields etc, "
               "not " + item + following() );
    }

    s->id = item;
    require( "]" );

    // Parse any range specification.
    if ( nextChar() == '<' ) {
        s->partial = true;
        step();
        s->offset = number();
        require( "." );
        s->length = nzNumber();
        require( ">" );
    }

    d->sections.append( s );
}


void Fetch::execute()
{
    ImapSession * s = imap()->session();

    if ( d->state == Initial ) {
        d->state = Responding;
        removeInvalidUids();
        sendFetchQueries();
    }

    uint i = 1;
    while ( i <= d->set.count() ) {
        uint uid = d->set.value( i );
        Message * m = s->message( uid );
        if ( ( !d->needHeader || m->hasHeaders() ) &&
             ( !d->needBody || m->hasBodies() ) &&
             ( !d->flags || m->hasExtraFlags() ) )
        {
            respond( fetchResponse( m, uid, s->msn( uid ) ), Untagged );
            d->set.remove( uid );
        }
        else {
            i++;
        }
    }

    if ( d->set.isEmpty() )
        finish();
}


/*! Removes any UIDs from d->set that do not have an associated message.
*/

void Fetch::removeInvalidUids()
{
    ImapSession * s = imap()->session();

    uint i = d->set.count();
    while ( i > 0 ) {
        uint uid = d->set.value( i );
        Message * m = s->message( uid );
        if ( !m )
            d->set.remove( uid );
        i--;
    }
}


/*! Issues queries to resolve any questions this FETCH needs to answer.
*/

void Fetch::sendFetchQueries()
{
    ImapSession * s = imap()->session();

    uint i = 1;
    while ( i <= d->set.count() ) {
        uint uid = d->set.value( i );
        Message * m = s->message( uid );
        if ( d->needHeader && !m->hasHeaders() )
            m->fetchHeaders( this );
        if ( d->needBody && !m->hasBodies() )
            m->fetchBodies( this );
        if ( d->flags && !m->hasExtraFlags() )
            m->fetchExtraFlags( this );
        i++;
    }
}


/* This function returns the response data for an element in
   d->sections, to be included in the FETCH response by
   fetchResponses() below.
*/

static String sectionResponse( FetchData::Section *s,
                               Message *m )
{
    String item, data;

    if ( s->id == "rfc822" ) {
        item = s->id.upper();
        data = m->rfc822();
    }

    else if ( s->id == "mime" ||
              s->id == "rfc822.header" ||
              s->id.startsWith( "header" ) )
    {
        bool mime = s->id == "mime";
        bool rfc822 = s->id == "rfc822.header";
        bool fields = s->id.startsWith( "header.fields" );
        bool exclude = s->id.endsWith( ".not" );

        Header *hdr = m->header();
        if ( !s->part.isEmpty() ) {
            BodyPart *bp = m->bodyPart( s->part, false );
            if ( bp && bp->header() )
                hdr = bp->header();
            else
                hdr = 0;
        }

        List< HeaderField >::Iterator it = 0;
        if ( hdr )
            it = hdr->fields()->first();
        while ( it ) {
            if ( !fields ||
                 ( !exclude && s->fields.find( it->name() ) ) ||
                 ( exclude && !s->fields.find( it->name() ) ) )
            {
                String n = it->name().headerCased();
                data.append( n + ": " + it->value() + "\r\n" );
            }
            ++it;
        }

        item = s->id.upper();
        if ( !rfc822 && !mime )
            item = "BODY[" + item;
        if ( fields )
            item.append( " (" + s->fields.join( " " ) + ")]" );
        data.append( "\r\n" );
    }

    else if ( s->id.isEmpty() ) {
        if ( s->part.isEmpty() ) {
            data = m->rfc822();
        }
        else {
            BodyPart *bp = m->bodyPart( s->part, false );
            if ( bp )
                data = bp->asText();
        }
        item = "BODY[" + s->part + "]";
    }

    if ( s->partial ) {
        item.append( "<" + fn( s->offset ) + ">" );
        data = data.mid( s->offset, s->length );
    }

    return item + " " + Command::imapQuoted( data, Command::NString );
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
        l.append( "RFC822.SIZE " + fn( m->rfc822Size() ) );
    if ( d->flags )
        l.append( "FLAGS (" + flagList( m, uid ) + ")" );
    if ( d->internaldate )
        l.append( "INTERNALDATE " + internalDate( m ) );
    if ( d->envelope )
        l.append( "ENVELOPE " + envelope( m ) );
    if ( d->body )
        l.append( "BODY " + bodyStructure( m, false ) );
    if ( d->bodystructure )
        l.append( "BODYSTRUCTURE " + bodyStructure( m, true ) );

    List< FetchData::Section >::Iterator it( d->sections.first() );
    while ( it ) {
        l.append( sectionResponse( it, m ) );
        ++it;
    }

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
    return "\"" + date.imap() + "\"";
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
    r.append( imapQuoted( h->messageId(), NString ) );

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

String Fetch::bodyStructure( Multipart * m, bool extended )
{
    String r;

    Header *hdr = m->header();
    ContentType *ct = hdr->contentType();

    if ( ct->type() == "multipart" ) {
        StringList children;
        List< BodyPart >::Iterator it( m->children()->first() );
        while ( it ) {
            children.append( bodyStructure( it, extended ) );
            ++it;
        }

        r = "(" + children.join( "" ) +
            " " + imapQuoted( ct->subtype() );
        if ( extended )
            r.append( "" );
        r.append( ")" );
    }
    else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // XXX: This doesn't handle the case where the top-level message
        // has Content-Type: message/rfc822.
        r = singlePartStructure( (BodyPart *)m, extended );
    }
    else {
        /* If we get here, m is either a single-part leaf BodyPart, or a
           Message. In the former case, it will have no children(), but
           the Message will have one child. */
        BodyPart *bp = m->children()->first();
        if ( !bp )
            bp = (BodyPart *)m;
        r = singlePartStructure( bp, extended );
    }

    return r;
}


/*! Returns the structure of the single-part bodypart \a bp. If
    \a extended is true, extended BODYSTRUCTURE attributes are
    included.
*/

String Fetch::singlePartStructure( BodyPart *bp, bool extended )
{
    StringList l;

    if ( !bp )
        return "";
    
    Header *hdr = bp->header();
    ContentType *ct = hdr->contentType();

    l.append( imapQuoted( ct->type() ) );
    l.append( imapQuoted( ct->subtype() ) );

    StringList *params = ct->parameterList();
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

    l.append( imapQuoted( hdr->messageId( HeaderField::ContentId ), NString ) );
    l.append( imapQuoted( hdr->contentDescription(), NString ) );

    if ( hdr->contentTransferEncoding() ) {
        switch( hdr->contentTransferEncoding()->encoding() ) {
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

    l.append( fn( bp->numBytes() ) );

    if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // body-type-msg   = media-message SP body-fields SP envelope
        //                   SP body SP body-fld-lines

        l.append( envelope( bp->rfc822() ) );
        l.append( bodyStructure( bp->rfc822(), extended ) );
        l.append( fn( bp->numLines() ) );
    }
    else if ( ct->type() == "text" ) {
        // body-type-text  = media-text SP body-fields SP body-fld-lines

        l.append( fn( bp->numLines() ) );
    }

    return "(" + l.join( " " ) + ")";
}
