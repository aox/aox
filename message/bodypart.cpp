// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "bodypart.h"

#include "cp.h"
#include "utf.h"
#include "codec.h"
#include "header.h"
#include "iso8859.h"
#include "ustring.h"
#include "message.h"
#include "unknown.h"
#include "iso2022jp.h"
#include "mimefields.h"


class BodypartData
    : public Garbage
{
public:
    BodypartData()
        : number( 1 ), message( 0 ),
          numBytes( 0 ), numEncodedBytes(), numEncodedLines( 0 ),
          hasText( false )
    {}

    uint number;

    Message * message;

    uint numBytes;
    uint numEncodedBytes;
    uint numEncodedLines;

    String data;
    UString text;
    bool hasText;
    String error;
};


/*! \class Bodypart bodypart.h

    The Bodypart class models a single MIME body part. It is a subclass
    of Multipart, and an adjunct to Message.

    Every Bodypart has a number(), and contains text(), data(), or a
    message(), based on its contentType(). It knows how many numBytes(),
    numEncodedBytes() and numEncodedLines() of data it contains, and can
    present itself asText().

    This class is also responsible for parsing bodyparts in messages.
*/

/*! Constructs an empty Bodypart.
    This is meant to be used only by parseBodypart().
*/

Bodypart::Bodypart()
    : d ( new BodypartData )
{
    setHeader( new Header( Header::Mime ) );
}


/*! Constructs a Bodypart with number \a n and parent \a p. */

Bodypart::Bodypart( uint n, Multipart * p )
    : d( new BodypartData )
{
    setHeader( new Header( Header::Mime ) );
    d->number = n;
    setParent( p );
}


/*! Returns a number that reflects this Bodypart's position within its
    containing Multipart.
*/

uint Bodypart::number() const
{
    return d->number;
}


/*! Returns the ContentType of this Bodypart, which may be a null
    pointer in case the Content-Type is the default one. The default
    is either text/plain or message/rfc822.

    The Bodypart cannot find the default alone, since it depends on
    the surrounding type.
*/

ContentType * Bodypart::contentType() const
{
    ContentType * ct = header()->contentType();
    if ( ct )
        return ct;
    if ( !parent() )
        return 0;
    ct = parent()->header()->contentType();
    if ( ct ) {
        if ( ct->type() == "multipart" ) {
            ct = 0;
        }
        else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
            Bodypart * bp = parent()->children()->firstElement();
            ct = bp->header()->contentType();
        }
    }
    return ct;
}


/*! Returns the content transfer encoding of this Bodypart, which may
    be any of String::Binary, String::QuotedPrintable and
    String::Base64.

    Note that data() and text() return the canonical representation of
    the body, not encoded with this.
*/

String::Encoding Bodypart::contentTransferEncoding() const
{
    ContentTransferEncoding * cte = header()->contentTransferEncoding();
    if ( !cte && parent() ) {
        ContentType * ct = parent()->header()->contentType();
        if ( !ct || ( ct->type() != "multipart" &&
                      ct->type() != "message" ) )
            cte = parent()->header()->contentTransferEncoding();
    }
    if ( cte )
        return cte->encoding();
    return String::Binary;
}


/*! Returns this Bodypart's content in 8-bit form. If this Bodypart is
    a text part, data() returns the UTF-encoded version of text().
*/

String Bodypart::data() const
{
    return d->data;
}


/*! Sets the data of this Bodypart to \a s. For use only by
    MessageBodyFetcher for now.
*/

void Bodypart::setData( const String &s )
{
    d->data = s;
}


/*! Returns the text of this Bodypart. MUST NOT be called for non-text
    parts (whose contents are not known to be well-formed text).
*/

UString Bodypart::text() const
{
    // When retrieved from the database, a text bodypart will have the
    // correct d->data, but d->text will not be set (because the text
    // may be shared with an existing non-text bodyparts entry).
    if ( !d->hasText ) {
        Utf8Codec u;
        d->text = u.toUnicode( d->data );
        d->hasText = true;
    }

    return d->text;
}


/*! Sets the text of this Bodypart to \a s. For use only by
    MessageBodyFetcher for now.
*/

void Bodypart::setText( const UString &s )
{
    d->text = s;
}


/*! Notifies this Bodypart that it contains \a n bytes of data().
    The initial value is 0.
*/

void Bodypart::setNumBytes( uint n )
{
    d->numBytes = n;
}


/*! Returns the number of bytes in this body part, as set using
    setNumBytes().
*/

uint Bodypart::numBytes() const
{
    return d->numBytes;
}


/*! Returns the value set by setNumEncodedBytes(). Compare to
    numBytes().
*/

uint Bodypart::numEncodedBytes() const
{
    return d->numEncodedBytes;
}


/*! Notifies this Bodypart that it contains \a n bytes of asText()
    when fully encoded using the current ContentTransferEncoding.  The
    initial value is 0.

    Compare to numBytes(), which returns the raw number of bytes.
*/

void Bodypart::setNumEncodedBytes( uint n )
{
    d->numEncodedBytes = n;
}


/*! Notifies this Bodypart that it contains \a n lines of text() once
    encoded some ContentTransferEncoding. The initial value is 0.
*/

void Bodypart::setNumEncodedLines( uint n )
{
    d->numEncodedLines = n;
}


/*! Returns the number of lines in this body part, as set using
    setNumEncodedLines().
*/

uint Bodypart::numEncodedLines() const
{
    return d->numEncodedLines;
}


/*! Returns the text representation of this Bodypart.

    Notes: This function seems uncomfortable. It returns just one of
    many possible text representations, and the exact choice seems
    arbitrary, and finally, it does rather overlap with text() and
    data().

    We probably should transition away from this function.

    The exact representation returned uses base64 encoding for data
    types and no ContentTransferEncoding. For text types, it encodes
    the text according to the ContentType.
*/

String Bodypart::asText() const
{
    String r;
    Codec *c = 0;

    ContentType *ct = header()->contentType();
    if ( ct && !ct->parameter( "charset" ).isEmpty() )
        c = Codec::byName( ct->parameter( "charset" ) );
    if ( !c )
        c = new AsciiCodec;

    if ( !children()->isEmpty() )
        appendMultipart( r );
    else if ( !header()->contentType() ||
              header()->contentType()->type() == "text" )
        r = c->fromUnicode( text() );
    else
        r = d->data.e64( 72 );

    return r;
}



/*! Parses the part of \a rfc2822 from index \a i to (but not including)
    \a end, dividing the part into bodyparts wherever the boundary \a
    divider occurs and adding each bodypart to \a children, and setting
    the correct \a parent. \a divider does not contain the leading or
    trailing hyphens. \a digest is true for multipart/digest and false
    for other types.
*/

void Bodypart::parseMultipart( uint i, uint end,
                               const String & rfc2822,
                               const String & divider,
                               bool digest,
                               List<Bodypart> * children,
                               Bodypart *parent )
{
    uint start = 0;
    bool last = false;
    uint pn = 1;
    while ( !last && i <= end ) {
        if ( i >= end ||
             ( rfc2822[i] == '-' && rfc2822[i+1] == '-' &&
               ( i == 0 || rfc2822[i-1] == 13 || rfc2822[i-1] == 10 ) &&
               rfc2822[i+2] == divider[0] &&
               rfc2822.mid( i+2, divider.length() ) == divider ) )
        {
            uint j = i;
            bool l = false;
            if ( i >= end ) {
                l = true;
            }
            else {
                j = i + 2 + divider.length();
                if ( rfc2822[j] == '-' && rfc2822[j+1] == '-' ) {
                    j += 2;
                    l = true;
                }
            }
            while ( rfc2822[j] == ' ' || rfc2822[j] == '\t' )
                j++;
            if ( rfc2822[j] == 13 || rfc2822[j] == 10 ||
                 j >= rfc2822.length() ) {
                // finally. we accept that as a boundary line.
                if ( rfc2822[j] == 13 )
                    j++;
                if ( rfc2822[j] == 10 )
                    j++;
                if ( start > 0 ) {
                    Header * h = Message::parseHeader( start, j,
                                                       rfc2822,
                                                       Header::Mime );
                    if ( digest )
                        h->setDefaultType( Header::MessageRfc822 );

                    // Strip the [CR]LF that belongs to the boundary.
                    if ( rfc2822[i-1] == 10 ) {
                        i--;
                        if ( rfc2822[i-1] == 13 )
                            i--;
                    }

                    Bodypart * bp = parseBodypart( start, i, rfc2822, h );
                    bp->d->number = pn;
                    children->append( bp );
                    bp->setParent( parent );
                    pn++;
                }
                last = l;
                start = j;
                i = j;
            }
        }
        while ( i < end && rfc2822[i] != 13 && rfc2822[i] != 10 )
            i++;
        while ( i < end && ( rfc2822[i] == 13 || rfc2822[i] == 10 ) )
            i++;
    }
}


static Codec * guessTextCodec( const String & body )
{
    // step 1. try iso-2022-jp. this goes first because it's so
    // restrictive, and because 2022 strings also match the ascii and
    // utf-8 tests.
    if ( body[0] == 0x1B &&
         ( body[1] == '(' || body[1] == '$' ) &&
         ( body[2] == 'B' || body[2] == 'J' || body[2] == '@' ) ) {
        Codec * c = new Iso2022JpCodec;
        c->toUnicode( body );
        if ( c->wellformed() )
            return c;
    }

    // step 2. could it be pure ascii?
    Codec * a = new AsciiCodec;
    (void)a->toUnicode( body );
    if ( a->wellformed() )
        return a;

    // some multibyte encodings have to go before utf-8, or else utf-8
    // will match. this applies at least to iso-2002-jp, but may also
    // apply to other encodings that use octet values 0x01-0x07f
    // exclusively.

    // step 3. does it look good as utf-8?
    Codec * u = new Utf8Codec;
    (void)u->toUnicode( body );
    if ( u->wellformed() ) {
        // if it's actually ascii, return that.
        if ( a->valid() )
            return a;
        return u;
    }

    // step 4. guess a codec based on the bodypart content.
    Codec * g = Codec::byString( body );
    if ( g ) {
        // this probably isn't necessary... but it doesn't hurt to be sure.
        (void)g->toUnicode( body );
        if ( g->wellformed() )
            return g;
    }

    // step 5. is utf-8 at all plausible?
    if ( u->valid() )
        return u;
    // should we use g here if valid()?

    return 0;
}


static Codec * guessHtmlCodec( const String & body )
{
    // Let's see if the general function has something for us.
    Codec * c = guessTextCodec( body );
    if ( c )
        return c;

    // HTML prescribes that 8859-1 is the default. Let's see if 8859-1
    // works.
    c = new Iso88591Codec;
    (void)c->toUnicode( body );
    if ( c->valid() )
        return c;
    // Some people believe that Windows codepage 1252 is HTML. Let's
    // see if that works.
    c = new Cp1252Codec;
    (void)c->toUnicode( body );
    if ( c->valid() )
        return c;

    // Nothing doing.
    return 0;
}


/*! Parses the part of \a rfc2822 from \a start to \a end (not
    including \a end) as a single bodypart with MIME/RFC 822 header \a h.

    This removes the "charset" argument from the Content-Type field in \a h.
*/

Bodypart * Bodypart::parseBodypart( uint start, uint end,
                                    const String & rfc2822,
                                    Header * h )
{
    if ( rfc2822[start] == 13 )
        start++;
    if ( rfc2822[start] == 10 )
        start++;

    Bodypart * bp = new Bodypart;
    bp->setHeader( h );

    String::Encoding e = String::Binary;
    ContentTransferEncoding * cte = h->contentTransferEncoding();
    if ( cte )
        e = cte->encoding();

    String body;
    if ( end > start )
        body = rfc2822.mid( start, end-start ).crlf().decode( e );

    ContentType * ct = h->contentType();
    if ( !ct ) {
        switch ( h->defaultType() ) {
        case Header::TextPlain:
            h->add( "Content-Type", "text/plain" );
            break;
        case Header::MessageRfc822:
            h->add( "Content-Type", "message/rfc822" );
            break;
        }
        ct = h->contentType();
    }
    if ( ct->type() == "text" ) {
        bool specified = false;
        bool unknown = false;
        Codec * c = 0;

        if ( ct->type() == "text" && ct->subtype() == "html" ) {
            // Some user-agents add a <meta http-equiv="content-type">
            // instead of the Content-Type field. We scan for that, to
            // work around certain observed breakage.
            //
            // This isn't correct because:
            // 1. This isn't HTTP, so http-equiv is irrelevant.
            // 2. We're just scanning for the particular pattern which
            // happens to be used by the brokenware, not parsing HTML.
            //
            // XXX: I wonder if this code shouldn't be invoked only if
            // no charset is specified in the MIME header, or if there
            // is an error using the specified charset (i.e., a dozen
            // lines lower).

            String b = body.lower().simplified();

            int i = 0;
            while ( i >= 0 ) {
                i = b.find( "<meta http-equiv=\"content-type\" content=\"", i );
                if ( i >= 0 ) {
                    i = i + 41; // length of the meta above
                    int j = i;
                    while ( j < (int)b.length() && b[j] != '"' )
                        j++;
                    HeaderField * hf
                        = HeaderField::create( "Content-Type",
                                               b.mid( i, j-i ) );
                    String cs = ((MimeField*)hf)->parameter( "charset" );
                    Codec * meta = 0;
                    if ( !cs.isEmpty() )
                        meta = Codec::byName( cs );
                    if ( meta )
                        meta->toUnicode( body );
                    if ( c )
                        c->toUnicode( body );
                    if ( meta && 
                         ( meta->wellformed() ||
                           ( meta->valid() && !c ) ||
                           ( meta->valid() && c && !c->valid() ) ) ) {
                        ct->removeParameter( "charset" );
                        ct->addParameter( "charset", meta->name().lower() );
                        i = -1;
                        specified = true;
                    }
                }
            }
        }

        if ( ct ) {
            String csn = ct->parameter( "charset" );
            if ( csn.lower() == "default" )
                csn = "";
            if ( !csn.isEmpty() )
                specified = true;
            c = Codec::byName( csn );
            if ( !c )
                unknown = true;
            if ( c && c->name().lower() == "us-ascii" ) {
                // Some MTAs appear to say this in case there is no
                // Content-Type field - without checking whether the
                // body actually is ASCII. If it isn't, we'd better
                // call our charset guesser.
                (void)c->toUnicode( body );
                if ( !c->valid() )
                    specified = false;
                // Not pretty.
            }
        }

        if ( !c )
            c = new AsciiCodec;

        bp->d->hasText = true;
        bp->d->text = c->toUnicode( body.crlf() );

        if ( !c->valid() && c->name() == "GB2312" ) {
            // undefined code point usage in GB2312 spam is much too
            // common. (GB2312 spam is much too common, but that's
            // another matter.) Gb2312Codec turns all undefined code
            // points into U+FFFE, so here, we can take the unicode
            // form and say it's the canonical form. when a client
            // later reads the message, it gets the text in unicode,
            // including U+FFFE.
            
            // the header may contain some unencoded gb2312. we bang
            // it by hand, ignoring errors.
            List<HeaderField>::Iterator hf( h->fields() );
            while ( hf ) {
                if ( !hf->parsed() &&
                     hf->type() == HeaderField::Subject ) {
                    // is it right to bang only Subject?
                    UString u = c->toUnicode( hf->value() );
                    Utf8Codec utf8;
                    String s( utf8.fromUnicode( u ) );
                    hf->setData( HeaderField::encodeText( s ) );
                }
                ++hf;
            }

            // bp->d->text is already good(ish), so what we need to do
            // to the body is only:
            c = new Utf8Codec;
        }

        if ( ( !c->wellformed() && !specified ) ||
             ( !c->valid() && specified ) ) {
            Codec * g = 0;
            if ( ct && ct->subtype() == "html" )
                g = guessHtmlCodec( body );
            else
                g = guessTextCodec( body );
            UString guessed;
            if ( g )
                guessed = g->toUnicode( body );
            if ( !g ) {
                // if we couldn't guess anything, keep what we had if
                // it's valid or explicitly specified, else use
                // unknown-8bit.
                if ( !specified && !c->valid() ) {
                    c = new Unknown8BitCodec;
                    bp->d->text = c->toUnicode( body );
                }
            }
            else {
                // if we could guess something, is our guess better
                // than what we had?
                if ( g->wellformed() && !c->wellformed() ) {
                    c = g;
                    bp->d->text = guessed;
                }
            }
        }

        if ( !c->valid() && bp->d->error.isEmpty() ) {
            bp->d->error = "Could not convert body to Unicode";
            if ( specified ) {
                String cs;
                if ( ct )
                    cs = ct->parameter( "charset" );
                if ( cs.isEmpty() )
                    cs = c->name();
                bp->d->error.append( " from " + cs );
            }
            if ( specified && unknown )
                bp->d->error.append( ": Character set not implemented" );
            else if ( !c->error().isEmpty() )
                bp->d->error.append( ": " + c->error() );
        }

        if ( c->name().lower() != "us-ascii" )
            ct->addParameter( "charset", c->name().lower() );
        else if ( ct )
            ct->removeParameter( "charset" );

        body = c->fromUnicode( bp->d->text );
        bool qp = body.needsQP();

        if ( cte ) {
            if ( !qp ) {
                h->removeField( HeaderField::ContentTransferEncoding );
                cte = 0;
            }
            else if ( cte->encoding() != String::QP ) {
                cte->setEncoding( String::QP );
            }
        }
        else if ( qp ) {
            h->add( "Content-Transfer-Encoding", "quoted-printable" );
            cte = h->contentTransferEncoding();
        }
    }
    else {
        bp->d->data = body;
        if ( ct->type() != "multipart" && ct->type() != "message" ) {
            e = String::Base64;
            // there may be exceptions. cases where some format really
            // needs another content-transfer-encoding:
            if ( ct->type() == "application" &&
                 ct->subtype() == "pgp-encrypted" &&
                 !body.needsQP() ) {
                // seems some PGP things need "Version: 1" unencoded
                e = String::Binary;
            }
            else if ( ct->type() == "application" &&
                      ct->subtype() == "octet-stream" &&
                      !body.needsQP() &&
                      body.contains( "BEGIN PGP MESSAGE" ) ) {
                // mutt cannot handle PGP in base64 (what a crock)
                e = String::Binary;
            }
            // change c-t-e to match the encoding decided above
            if ( e == String::Binary ) {
                h->removeField( HeaderField::ContentTransferEncoding );
                cte = 0;
            }
            else if ( cte ) {
                cte->setEncoding( e );
            }
            else {
                h->add( "Content-Transfer-Encoding", "base64" );
                cte = h->contentTransferEncoding();
            }
        }
    }

    bp->d->numBytes = body.length();
    if ( cte )
        body = body.encode( cte->encoding(), 72 );
    bp->d->numEncodedBytes = body.length();

    if ( bp->d->hasText ||
         ( ct->type() == "message" && ct->subtype() == "rfc822" ) )
    {
        uint n = 0;
        uint i = 0;
        uint l = body.length();
        while ( i < l ) {
            if ( body[i] == '\n' )
                n++;
            i++;
        }
        if ( l && body[l-1] != '\n' )
            n++;
        bp->setNumEncodedLines( n );
    }

    if ( ct->type() == "multipart" ) {
        parseMultipart( start, end, rfc2822,
                        ct->parameter( "boundary" ),
                        ct->subtype() == "digest",
                        bp->children(), bp );
    }
    else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // There are sometimes blank lines before the message.
        while ( rfc2822[start] == 13 || rfc2822[start] == 10 )
            start++;
        Message * m = new Message( rfc2822.mid( start, end-start ) );
        List<Bodypart>::Iterator it( m->children() );
        while ( it ) {
            bp->children()->append( it );
            it->setParent( bp );
            ++it;
        }
        bp->setMessage( m );
        m->setParent( bp );
    }

    h->simplify();

    return bp;
}


/*! Returns a pointer to the subsidiary message, provided this is a
    message/rfc822 bodypart, or a null pointer in other cases.
*/

Message * Bodypart::message() const
{
    return d->message;
}


/*! Notifies this Bodypart that it has a subsidiary message \a m. This
    function is only meaningful if the Bodypart has content-type
    message/rfc822.
*/

void Bodypart::setMessage( Message * m )
{
    d->message = m;
}


/*! Returns true. */

bool Bodypart::isBodypart() const
{
    return true;
}


/*! Returns an error message describing why this bodypart is bad, or
    an empty string if nothing seems to be the matter.
*/

String Bodypart::error() const
{
    return d->error;
}
