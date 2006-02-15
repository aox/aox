// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "bodypart.h"

#include "utf.h"
#include "codec.h"
#include "header.h"
#include "iso8859.h"
#include "ustring.h"
#include "message.h"
#include "unknown.h"
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
    if ( ct && ct->type() == "multipart" )
        return 0;
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

    In case of error, \a error is set to a suitable error message. If
    \a error is nonempty, it isn't changed.
*/

void Bodypart::parseMultipart( uint i, uint end,
                               const String & rfc2822,
                               const String & divider,
                               bool digest,
                               List<Bodypart> * children,
                               Bodypart *parent,
                               String & error )
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
                    if ( h->contentType() )
                        ; // if supplied, it's good.
                    else if ( digest )
                        h->add( "Content-Type", "message/rfc822" );
                    else
                        h->add( "Content-Type", "text/plain" );

                    // Strip the [CR]LF that belongs to the boundary.
                    if ( rfc2822[i-1] == 10 ) {
                        i--;
                        if ( rfc2822[i-1] == 13 )
                            i--;
                    }

                    Bodypart * bp = parseBodypart( start, i, rfc2822, h,
                                                   error );
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
    // step 1. could it be pure ascii?
    Codec * c = new AsciiCodec;
    (void)c->toUnicode( body );
    if ( c->valid() )
        return c;

    // step 2. could it be utf-8?
    c = new Utf8Codec;
    (void)c->toUnicode( body );
    if ( c->valid() )
        return c;

    // step 3. could it be ... (we probably want to check Big5, GB18030
    // and other multibytes here.)

    // step 4. guess a codec based on the bodypart content.
    c = Codec::byString( body );
    if ( c ) {
        // this probably isn't necessary... but it doesn't hurt to be sure.
        (void)c->toUnicode( body );
        if ( c->valid() )
            return c;
    }

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

    // Nothing doing.
    return 0;
}


/*! Parses the part of \a rfc2822 from \a start to \a end (not
    including \a end) as a single bodypart with MIME/RFC822 header \a h.

    This removes the "charset" argument from the Content-Type field in \a h.
*/

Bodypart * Bodypart::parseBodypart( uint start, uint end,
                                    const String & rfc2822,
                                    Header * h, String & error )
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
        body = rfc2822.mid( start, end-start ).decode( e );

    ContentType * ct = h->contentType();
    if ( !ct || ct->type() == "text" ) {
        bool specified = false;
        Codec * c = 0;

        if ( ct && ct->type() == "text" && ct->subtype() == "html" ) {
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

            String b = body.mid( 0, 2048 ).lower().simplified();

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
                    if ( !cs.isEmpty() && Codec::byName( cs ) != 0 ) {
                        // XXX: If ct does specify a charset, we should
                        // try to figure out which of the two is more
                        // appropriate to this message, instead of just
                        // zapping the mail one with the HTTP one.
                        ct->removeParameter( "charset" );
                        ct->addParameter( "charset", cs );
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
        bp->d->text = c->toUnicode( body );

        if ( !c->valid() && !specified ) {
            if ( ct && ct->subtype() == "html" )
                c = guessHtmlCodec( body );
            else
                c = guessTextCodec( body );
            if ( !c )
                c = new Unknown8BitCodec;
            bp->d->text = c->toUnicode( body );
        }

        if ( !c->valid() && error.isEmpty() ) {
            String cs;
            if ( ct && specified )
                cs = ct->parameter( "charset" );
            if ( cs.isEmpty() )
                cs = c->name();
            error = "Could not convert body to Unicode from " + cs;
            if ( !c->error().isEmpty() &&
                 ct->parameter( "charset" ).lower() == c->name().lower() )
                error.append( ": " + c->error() );
        }

        if ( c->name().lower() != "us-ascii" ) {
            if ( !ct ) {
                h->add( "Content-Type", "text/plain" );
                ct = h->contentType();
            }
            ct->addParameter( "charset", c->name().lower() );
        }
        else if ( ct ) {
            ct->removeParameter( "charset" );
        }

        // XXX: Can we avoid this re-conversion?
        body = c->fromUnicode( bp->d->text );
        bool qp = body.needsQP();

        if ( cte ) {
            if ( !qp )
                h->removeField( HeaderField::ContentTransferEncoding );
            else if ( cte->encoding() != String::QP )
                cte->setEncoding( String::QP );
        }
        else if ( qp ) {
            h->add( "Content-Transfer-Encoding", "quoted-printable" );
        }
        h->simplify();
    }
    else {
        bp->d->data = body;
        if ( ct->type() != "multipart" && ct->type() != "message" ) {
            if ( cte ) {
                if ( cte->encoding() != String::Base64 )
                    cte->setEncoding( String::Base64 );
            }
            else {
                h->add( "Content-Transfer-Encoding", "base64" );
                cte = h->contentTransferEncoding();
            }
            h->simplify();
        }
    }

    bp->d->numBytes = body.length();
    if ( cte )
        body = body.encode( cte->encoding() );
    // XXX: if cte->encoding() is base64, this encodes without
    // CFLF. that seems rather suboptimal.
    bp->d->numEncodedBytes = body.length();

    if ( bp->d->hasText ||
         ( ct && ct->type() == "message" && ct->subtype() == "rfc822" ) )
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

    if ( !ct ) {
        ;
    }
    else if ( ct->type() == "multipart" ) {
        parseMultipart( start, end, rfc2822,
                        ct->parameter( "boundary" ),
                        ct->subtype() == "digest",
                        bp->children(), bp, error );
    }
    else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
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
