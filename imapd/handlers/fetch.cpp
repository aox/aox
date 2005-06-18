// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fetch.h"

#include "imapsession.h"
#include "messageset.h"
#include "stringlist.h"
#include "mimefields.h"
#include "bodypart.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "scope.h"
#include "store.h"
#include "query.h"
#include "imap.h"
#include "flag.h"
#include "date.h"


class FetchData {
public:
    FetchData()
        : state( 0 ), peek( true ), uid( false ),
          flags( false ), envelope( false ),
          body( false ), bodystructure( false ),
          internaldate( false ), rfc822size( false ),
          needHeader( false ), needBody( false )
    {}

    class Section {
    public:
        Section()
            : binary( false ),
              partial( false ), offset( 0 ), length( UINT_MAX )
        {}

        String id;
        String part;
        StringList fields; 
        bool binary;
        bool partial;
        uint offset;
        uint length;
    };

    int state;
    bool peek;
    MessageSet set;

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

    Our parser used to be slightly more permissive than the RFC. This is
    a bug, and many of the problems have been corrected.
*/


/*! Creates a new handler for FETCH if \a u is false, or for UID FETCH
    if \a u is true.
*/

Fetch::Fetch( bool u )
    : Command(), d( new FetchData )
{
    d->uid = u;
}


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


void Fetch::parse()
{
    space();
    d->set = set( !d->uid );
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
        parseBody( false );
    }
    else if ( keyword == "body" ) {
        if ( nextChar() == '[' ) {
            d->peek = false;
            step();
            parseBody( false );
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
    else if ( keyword == "binary.peek" && nextChar() == '[' ) {
        step();
        parseBody( true );
    }
    else if ( keyword == "binary" && nextChar() == '[' ) {
        d->peek = false;
        step();
        parseBody( true );
    }
    else if ( keyword == "binary.size" && nextChar() == '[' ) {
        d->peek = false;
        step();
        parseBody( true );
        FetchData::Section * s = d->sections.last();
        s->id = "size";
        if ( s->partial )
            error( Bad, "Fetching partial BINARY.SIZE is not meaningful" );
    }
    else {
        error( Bad, "expected fetch attribute, saw word " + keyword );
    }
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

    If \a binary is true, the parsed section will be sent using the
    BINARY extension (RFC 3515). If not, it'll be sent using a normal
    BODY.
*/

void Fetch::parseBody( bool binary )
{
    FetchData::Section * s = new FetchData::Section;
    s->binary = binary;

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
    if ( binary && !item.isEmpty() ) {
        error( Bad, "BINARY with section-text is not legal, saw " + item );
    }
    else if ( item == "text" ) {
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

    if ( d->state == 0 ) {
        if ( !d->peek && s->readOnly() )
            d->peek = true;
        d->state = 1;
        sendFetchQueries();
    }

    uint i = 1;
    while ( i == 1 && !d->set.isEmpty() ) {
        uint uid = d->set.value( i );
        Message * m = s->mailbox()->message( uid );
        if ( ( !d->needHeader || m->hasHeaders() ) &&
             ( !d->needBody || m->hasBodies() ) &&
             ( !d->flags || m->hasFlags() ) &&
             ( ( !d->rfc822size && !d->internaldate ) || m->hasTrivia() ) )
        {
            imap()->enqueue( fetchResponse( m, uid, s->msn( uid ) ) );
            d->set.remove( uid );
        }
        else {
            i++;
        }
    }

    d->state = 2;

    if ( d->set.isEmpty() )
        finish();
}


/*! Issues queries to resolve any questions this FETCH needs to answer.
*/

void Fetch::sendFetchQueries()
{
    MessageSet headers, bodies, flags, trivia;
    Mailbox * mb = imap()->session()->mailbox();

    uint i = 1;
    while ( i <= d->set.count() ) {
        uint uid = d->set.value( i );
        Message * m = mb->message( uid );
        if ( d->needHeader && !m->hasHeaders() )
            headers.add( uid );
        if ( d->needBody && !m->hasBodies() )
            bodies.add( uid );
        if ( d->flags && !m->hasFlags() )
            flags.add( uid );
        if ( ( d->rfc822size || d->internaldate ) && !m->hasTrivia() )
            trivia.add( uid );
        i++;
    }

    mb->fetchFlags( flags, this );
    mb->fetchHeaders( headers, this );
    mb->fetchBodies( bodies, this );
    mb->fetchTrivia( trivia, this );

    // if we're not peeking, send off a query to set \seen, and don't
    // wait for any results.
    if ( d->peek )
        return;
    Flag * seen = Flag::find( "\\seen" );
    if ( !seen )
        return;
    Query * q = Store::addFlagsQuery( seen, imap()->session()->mailbox(),
                                      d->set, 0 );
    q->execute();
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
        bool rfc822 = s->id == "rfc822.header";
        bool fields = s->id.startsWith( "header.fields" );
        bool exclude = s->id.endsWith( ".not" );

        Header *hdr = m->header();
        if ( !s->part.isEmpty() ) {
            Bodypart *bp = m->bodypart( s->part, false );
            if ( bp && bp->header() )
                hdr = bp->header();
            else
                hdr = 0;
        }

        List< HeaderField >::Iterator it;
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
        if ( !rfc822 ) {
            if ( !s->part.isEmpty() )
                item = s->part + "." + item;
            item = "BODY[" + item;
            if ( fields )
                item.append( " (" + s->fields.join( " " ) + ")" );
            item.append( "]" );
        }
        data.append( "\r\n" );
    }

    else if ( s->id.isEmpty() ) {
        if ( s->part.isEmpty() ) {
            data = m->rfc822();
        }
        else if ( s->binary ) {
            Bodypart *bp = m->bodypart( s->part, false );
            if ( bp )
                data = bp->data();
        }
        else {
            Bodypart *bp = m->bodypart( s->part, false );
            if ( bp )
                data = bp->asText();
        }
        if ( s->binary )
            item = "BINARY";
        else
            item = "BODY";
        item = item + "[" + s->part + "]";
    }

    else if ( s->id == "text" ) {
        if ( s->part.isEmpty() ) {
            item = "TEXT";
            data = m->body();
        }
        else {
            item = s->part + ".TEXT";
            Bodypart *bp = m->bodypart( s->part, false );
            if ( bp && bp->rfc822() )
                data = bp->rfc822()->body();
        }
        item = "BODY[" + item + "]";
    }

    else if ( s->id == "size" ) {
        if ( s->part.isEmpty() ) {
            data = m->rfc822();
        }
        else {
            Bodypart *bp = m->bodypart( s->part, false );
            if ( bp )
                data = bp->data();
        }
        return "BINARY.SIZE[" + s->part + "] " + fn( data.length() );
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

    List< FetchData::Section >::Iterator it( d->sections );
    while ( it ) {
        l.append( sectionResponse( it, m ) );
        ++it;
    }

    String r = "* " + fn( msn ) + " FETCH (" + l.join( " " ) + ")\r\n";
    return r;
}


/*! Returns a string containing all the flags that are set for message
    \a m, which has UID \a uid.
*/

String Fetch::flagList( Message * m, uint uid )
{
    String r;

    if ( imap()->session()->isRecent( uid ) )
        r = "\\recent";

    List<Flag> * f = m->flags();
    if ( f && !f->isEmpty() ) {
        List<Flag>::Iterator it( f );
        while ( it ) {
            if ( !r.isEmpty() )
                r.append( " " );
            r.append( it->name() );
            ++it;
        }
    }

    return r;
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
    List<Address>::Iterator it( a );
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

    // envelope = "(" env-date SP env-subject SP env-from SP
    //                env-sender SP env-reply-to SP env-to SP env-cc SP
    //                env-bcc SP env-in-reply-to SP env-message-id ")"

    String r( "(" );

    Date * date = h->date();
    if ( date )
        r.append( imapQuoted( date->rfc822(), NString ) );
    else
        r.append( "NIL" );
    r.append( " " );

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
}


static String parameterString( MimeField *mf )
{
    StringList *p = 0;

    if ( mf )
        p = mf->parameters();
    if ( !mf || !p || p->isEmpty() )
        return "NIL";

    StringList l;
    StringList::Iterator it( p );
    while ( it ) {
        l.append( Command::imapQuoted( *it ) );
        l.append( Command::imapQuoted( mf->parameter( *it ) ) );
        ++it;
    }

    return "(" + l.join( " " ) + ")";
}


static String dispositionString( ContentDisposition *cd )
{
    if ( !cd )
        return "NIL";

    String s;
    switch ( cd->disposition() ) {
    case ContentDisposition::Inline:
        s = "inline";
        break;
    case ContentDisposition::Attachment:
        s = "attachment";
        break;
    }

    return "(\"" + s + "\" " + parameterString( cd ) + ")";
}


static String languageString( ContentLanguage *cl )
{
    if ( !cl )
        return "NIL";

    StringList m;
    const StringList *l = cl->languages();
    StringList::Iterator it( l );
    while ( it ) {
        m.append( Command::imapQuoted( *it ) );
        ++it;
    }

    if ( l->count() == 1 )
        return *m.first();
    return "(" + m.join( " " ) + ")";
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

    if ( ct && ct->type() == "multipart" ) {
        StringList children;
        List< Bodypart >::Iterator it( m->children() );
        while ( it ) {
            children.append( bodyStructure( it, extended ) );
            ++it;
        }

        r = "(" + children.join( "" ) +
            " " + imapQuoted( ct->subtype() );

        if ( extended ) {
            r.append( " " );
            r.append( parameterString( ct ) );
            r.append( " " );
            r.append( dispositionString( hdr->contentDisposition() ) );
            r.append( " " );
            r.append( languageString( hdr->contentLanguage() ) );
            r.append( " " );
            r.append( imapQuoted( hdr->contentLocation(), NString ) );
        }

        r.append( ")" );
    }
    else if ( ct && ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // XXX: This doesn't handle the case where the top-level message
        // has Content-Type: message/rfc822.
        r = singlePartStructure( (Bodypart *)m, extended );
    }
    else {
        /* If we get here, m is either a single-part leaf Bodypart, or a
           Message. In the former case, it will have no children(), but
           the Message will have one child. */
        Bodypart *bp = m->children()->first();
        if ( !bp )
            bp = (Bodypart *)m;
        r = singlePartStructure( bp, extended );
    }

    return r;
}


/*! Returns the structure of the single-part bodypart \a bp. If
    \a extended is true, extended BODYSTRUCTURE attributes are
    included.
*/

String Fetch::singlePartStructure( Bodypart *bp, bool extended )
{
    StringList l;

    if ( !bp )
        return "";

    Header *hdr = bp->header();
    ContentType *ct = hdr->contentType();

    if ( ct ) {
        l.append( imapQuoted( ct->type() ) );
        l.append( imapQuoted( ct->subtype() ) );
    }
    else {
        // XXX: What happens to the default if this is a /digest?
        l.append( "\"text\"" );
        l.append( "\"plain\"" );
    }

    l.append( parameterString( ct ) );
    l.append( imapQuoted( hdr->messageId( HeaderField::ContentId ), NString ) );
    l.append( imapQuoted( hdr->contentDescription(), NString ) );

    if ( hdr->contentTransferEncoding() ) {
        switch( hdr->contentTransferEncoding()->encoding() ) {
        case String::Binary:
            l.append( "\"8BIT\"" ); // hm. is this entirely sound?
            break;
        case String::Base64:
            l.append( "\"BASE64\"" );
            break;
        case String::QP:
            l.append( "\"QUOTED-PRINTABLE\"" );
            break;
        }
    }
    else {
        l.append( "\"7BIT\"" );
    }

    l.append( fn( bp->numEncodedBytes() ) );

    if ( ct && ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // body-type-msg   = media-message SP body-fields SP envelope
        //                   SP body SP body-fld-lines
        l.append( envelope( bp->rfc822() ) );
        l.append( bodyStructure( bp->rfc822(), extended ) );
        l.append( fn( bp->numEncodedLines() ) );
    }
    else if ( !ct || ct->type() == "text" ) {
        // body-type-text  = media-text SP body-fields SP body-fld-lines
        l.append( fn( bp->numEncodedLines() ) );
    }

    if ( extended ) {
        String md5;
        HeaderField *f = hdr->field( HeaderField::ContentMd5 );
        if ( f )
            md5 = f->value();

        l.append( imapQuoted( md5, NString ) );
        l.append( dispositionString( hdr->contentDisposition() ) );
        l.append( languageString( hdr->contentLanguage() ) );
        l.append( imapQuoted( hdr->contentLocation(), NString ) );
    }

    return "(" + l.join( " " ) + ")";
}
