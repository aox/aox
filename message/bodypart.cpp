// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
#include "log.h"


class BodypartData
    : public Garbage
{
public:
    BodypartData()
        : id( 0 ), number( 0 ), message( 0 ),
          numBytes( 0 ), numEncodedBytes(), numEncodedLines( 0 ),
          hasText( false )
    {}

    uint id;
    uint number;

    Message * message;

    uint numBytes;
    uint numEncodedBytes;
    uint numEncodedLines;

    EString data;
    UString text;
    bool hasText;
    bool isPgpSigned;
    EString error;
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
    setPgpSigned( false );
}


/*! Constructs a Bodypart with number \a n and parent \a p. */

Bodypart::Bodypart( uint n, Multipart * p )
    : d( new BodypartData )
{
    setHeader( new Header( Header::Mime ) );
    d->number = n;
    setParent( p );
    setPgpSigned( false );
}


/*! Returns a number that reflects this Bodypart's position within its
    containing Multipart.
*/

uint Bodypart::number() const
{
    return d->number;
}


/*! Returns the id of this bodypart in the bodyparts table, or 0 if it
    has not been stored there yet. */

uint Bodypart::id() const
{
    return d->id;
}


/*! Sets the id of this bodypart to \a id. Meant for use only by the
    Injector. */

void Bodypart::setId( uint id )
{
    d->id = id;
}


/*! Returns the ContentType of this Bodypart, which may be a null
    pointer in case the Content-Type is the default one. The default
    is either text/plain or message/rfc822.

    The Bodypart cannot find the default alone, since it depends on
    the surrounding type.
*/

ContentType * Bodypart::contentType() const
{
    ::log( "Bodypart::contentType", Log::Debug );
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
    be any of EString::Binary, EString::QuotedPrintable and
    EString::Base64.

    Note that data() and text() return the canonical representation of
    the body, not encoded with this.
*/

EString::Encoding Bodypart::contentTransferEncoding() const
{
    ::log( "Bodypart::contentTransferEncoding", Log::Debug );
    ContentTransferEncoding * cte = header()->contentTransferEncoding();
    if ( !cte && parent() ) {
        ContentType * ct = parent()->header()->contentType();
        if ( !ct || ( ct->type() != "multipart" &&
                      ct->type() != "message" ) )
            cte = parent()->header()->contentTransferEncoding();
    }
    if ( cte )
        return cte->encoding();
    return EString::Binary;
}


/*! Returns this Bodypart's content, provided it has an 8-bit type. If
    this Bodypart is a text part, data() returns an empty string.
*/

EString Bodypart::data() const
{
    return d->data;
}


/*! Sets the data of this Bodypart to \a s. For use only by
    MessageBodyFetcher for now.
*/

void Bodypart::setData( const EString &s )
{
    d->data = s;
}


/*! Returns the text of this Bodypart. MUST NOT be called for non-text
    parts (whose contents are not known to be well-formed text).
*/

UString Bodypart::text() const
{
    if ( d->hasText )
        return d->text;

    Utf8Codec c;
    return c.toUnicode( d->data );
}


/*! Sets the text of this Bodypart to \a s. For use only by
    MessageBodyFetcher for now.
*/

void Bodypart::setText( const UString &s )
{
    d->hasText = true;
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

EString Bodypart::asText( bool avoidUtf8 ) const
{
    EString r;
    Codec *c = 0;

    ContentType *ct = header()->contentType();
    if ( ct && !ct->parameter( "charset" ).isEmpty() )
        c = Codec::byName( ct->parameter( "charset" ) );
    if ( !c )
        c = new AsciiCodec;

    if ( !children()->isEmpty() ) {
        ::log( "Bodypart::asText - will appendMultipart text:" + r, Log::Debug );
        appendMultipart( r, avoidUtf8 );
    }
    else if ( !header()->contentType() ||
              header()->contentType()->type() == "text" ) {
              // ||
              // header()->contentType()->baseValue() == "application/pgp-signature" ) {  //hgu - fix for signatures
        if ( !header()->contentType() ) {
            ::log( "Bodypart::asText - contentType empty, using text", Log::Debug );
        } else {
            ::log( "Bodypart::asText - contentType=text", Log::Debug );
        }
        r = c->fromUnicode( text() );
    }
    else {
        ::log( "Bodypart::asText - cte:" +  header()->contentType()->baseValue() + " will return base64 encoded data", Log::Debug );
        r = d->data.e64( 72 );
    }

    ::log( "Bodypart::asText - text:" + r, Log::Debug );

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
                               const EString & rfc2822,
                               const EString & divider,
                               bool digest,
                               List< Bodypart > * children,
                               Multipart * parent,
                               bool pgpSigned )
{
    bool isPgpSigned = pgpSigned;
    ::log( "Bodypart::parseMultipart - text:" + rfc2822.mid(i, end - i), Log::Debug );
    if ( isPgpSigned ) 
        ::log( "Bodypart::parseMultipart - signed-flag:true", Log::Debug );
    else
        ::log( "Bodypart::parseMultipart - signed-flag:false", Log::Debug );
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
                    uint sigstart = start;  // hgu - remember were we started
                    ::log( "Bodypart::parseMultipart - will parseHeader", Log::Debug );
                    Header * h = Message::parseHeader( start, j,
                                                       rfc2822,
                                                       Header::Mime );
                    if ( digest )
                        h->setDefaultType( Header::MessageRfc822 );
    
                    ::log( "Bodypart::parseMultipart - will repair header:" + h->asText(false), Log::Debug );
                    h->repair();
    
                    // Strip the [CR]LF that belongs to the boundary.
                    if ( rfc2822[i-1] == 10 ) {
                        i--;
                        if ( rfc2822[i-1] == 13 )
                            i--;
                    }
    
                    if ( isPgpSigned ) {
                        ::log( "**** hgu **** signed mail, adding complete body:" + rfc2822.mid(sigstart, i - start),Log::Debug );
                        Bodypart * bpt = new Bodypart( 0, parent );
                        bpt->setPgpSigned( true );  // really needed ?
                        bpt->setData( rfc2822.mid(sigstart, i - sigstart) );
                        bpt->setNumBytes( i - sigstart );
                        children->append( bpt );
                        ::log( "**** hgu **** adding signed mail body completed", Log::Debug );
                        isPgpSigned = false;
                    }
  
                    ::log( "Bodypart::parseMultipart - will parseBodypart", Log::Debug );
                    Bodypart * bp =
                        parseBodypart( start, i, rfc2822, h, parent );
                    bp->d->number = pn;
                    children->append( bp );
                    pn++;
    
                    ::log( "Bodypart::parseMultipart - will repair header:" + bp->asText(false), Log::Debug );
                    h->repair( bp, "" );
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


static Codec * guessTextCodec( const EString & body )
{
    ::log( "Bodypart guessTextCodec", Log::Debug );
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


static Codec * guessHtmlCodec( const EString & body )
{
    ::log( "Bodypart guessHtmlCodec", Log::Debug );
    // Let's see if the general function has something for us.
    Codec * guess = guessTextCodec( body );

    // HTML prescribes that 8859-1 is the default. Let's see if 8859-1
    // works.
    if ( !guess ) {
        guess = new Iso88591Codec;
        (void)guess->toUnicode( body );
        if ( !guess->valid() )
            guess = 0;
    }

    if ( !guess ||
         ( !guess->wellformed() &&
           ( guess->name() == "ISO-8859-1" ||
             guess->name() == "ISO-8859-15" ) ) ) {
        // Some people believe that Windows codepage 1252 is
        // ISO-8859-1. Let's see if that works.
        Codec * windoze = new Cp1252Codec;
        (void)windoze->toUnicode( body );
        if ( windoze->wellformed() )
            guess = windoze;
    }


    // Some user-agents add a <meta http-equiv="content-type"> instead
    // of the Content-Type field. Maybe that exists? And if it exists,
    // is it more likely to be correct than our guess above?

    EString b = body.lower().simplified();
    int i = 0;
    while ( i >= 0 ) {
        EString tag( "<meta http-equiv=\"content-type\" content=\"" );
        i = b.find( tag, i );
        if ( i >= 0 ) {
            i = i + tag.length();
            int j = i;
            while ( j < (int)b.length() && b[j] != '"' )
                j++;
            HeaderField * hf
                = HeaderField::create( "Content-Type",
                                       b.mid( i, j-i ) );
            EString cs = ((MimeField*)hf)->parameter( "charset" );
            Codec * meta = 0;
            if ( !cs.isEmpty() )
                meta = Codec::byName( cs );
            UString m;
            if ( meta )
                m = meta->toUnicode( body );
            UString g;
            if ( guess )
                g = guess->toUnicode( body );
            if ( meta &&
                 ( ( !m.isEmpty() && m == g ) ||
                   ( meta->wellformed() &&
                     ( !guess || !guess->wellformed() ) ) ||
                   ( meta->valid() && !guess ) ||
                   ( meta->valid() && guess &&
                     guess->name() == "ISO-8859-1" ) ||
                   ( meta->valid() && guess && !guess->valid() ) ) &&
                 meta->toUnicode( b ).ascii().contains( tag ) ) {
                guess = meta;
            }
        }
    }

    return guess;
}


/*! Parses the part of \a rfc2822 from \a start to \a end (not
    including \a end) as a single bodypart with MIME/RFC 822 header \a h.

    This removes the "charset" argument from the Content-Type field in \a h.

    The \a parent argument is provided so that nested message/rfc822
    bodyparts without a Date field may be fixed with reference to the
    Date field in the enclosing bodypart.
*/

Bodypart * Bodypart::parseBodypart( uint start, uint end,
                                    const EString & rfc2822,
                                    Header * h, Multipart * parent )
{
    ::log( "Bodypart::parseBodypart - text:" + rfc2822.mid(start, end - start), Log::Debug );
    ::log( "Bodypart::parseBodypart - header:" + h->asText(false), Log::Debug );
    if ( rfc2822[start] == 13 )
        start++;
    if ( rfc2822[start] == 10 )
        start++;

    Bodypart * bp = new Bodypart;
    bp->setParent( parent );
    bp->setHeader( h );

    EString body;
    if ( end > start )
        body = rfc2822.mid( start, end-start );
    if ( !body.contains( '=' ) ) {
        // sometimes people send c-t-e: q-p _and_ c-t-e: 7bit or 8bit.
        // if they are equivalent we can accept it.
        uint i = 0;
        bool any = false;
        HeaderField * f = 0;
        while ( (f=h->field(HeaderField::ContentTransferEncoding,i)) != 0 ) {
            if ( ((ContentTransferEncoding*)f)->encoding() == EString::QP )
                any = true;
            i++;
        }
        if ( any && i > 1 ) {
            ::log( "Bodypart::parseBodypart - will removeField cte", Log::Debug );
            h->removeField( HeaderField::ContentTransferEncoding );
        }
    }

    EString::Encoding e = EString::Binary;
    ContentTransferEncoding * cte = h->contentTransferEncoding();
    if ( cte )
        e = cte->encoding();
    if ( !body.isEmpty() ) {
        if ( e == EString::Base64 || e == EString::Uuencode ) {
            body = body.decoded( e );
            ::log( "Bodypart::parseBodypart - decoding - base64 or uuencode", Log::Debug );
        } else {
            ::log( "Bodypart::parseBodypart - decoding - not base64", Log::Debug );
            body = body.crlf().decoded( e );
        }
    }
    ::log( "Bodypart::parseBodypart - decoded body:" + body, Log::Debug );

    ContentType * ct = h->contentType();
    if ( !ct ) {
        switch ( h->defaultType() ) {
        case Header::TextPlain:
            ::log( "Bodypart::parseBodypart - add ct=text/plain", Log::Debug );
            h->add( "Content-Type", "text/plain" );
            break;
        case Header::MessageRfc822:
            ::log( "Bodypart::parseBodypart - add ct=message/rfc822", Log::Debug );
            h->add( "Content-Type", "message/rfc822" );
            break;
        }
        ct = h->contentType();
    }
    if ( ct->type() == "text" ) {
        bool specified = false;
        bool unknown = false;
        Codec * c = 0;

        ::log( "Bodypart::parseBodypart - content-type is text", Log::Debug );
        if ( ct ) {
            EString csn = ct->parameter( "charset" );
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

        if ( c->name() == "GB2312" || c->name() == "ISO-2022-JP" ||
             c->name() == "KS_C_5601-1987" ) {
            // undefined code point usage in GB2312 spam is much too
            // common. (GB2312 spam is much too common, but that's
            // another matter.) Gb2312Codec turns all undefined code
            // points into U+FFFD, so here, we can take the unicode
            // form and say it's the canonical form. when a client
            // later reads the message, it gets the text in unicode,
            // including U+FFFD.

            bool bad = !c->valid();

            // the header may contain some unencoded gb2312. we bang
            // it by hand, ignoring errors.
            List<HeaderField>::Iterator hf( h->fields() );
            while ( hf ) {
                if ( !hf->valid() &&
                     hf->type() == HeaderField::Subject ) {
                    // is it right to bang only Subject?
                    c->reset();
                    hf->setValue( c->toUnicode( hf->unparsedValue() ) );
                }
                ++hf;
            }

            // if the body was bad, we prefer the (unicode) in
            // bp->d->text and pretend it arrived as UTF-8:
            if ( bad ) {
                c = new Utf8Codec;
                body = c->fromUnicode( bp->d->text );
            }
        }
        ::log( "Bodypart::parseBodypart - guessing html codec", Log::Debug );

        if ( ( !specified && ( !c->wellformed() ||
                               ct->subtype() == "html" ) ) ||
             ( specified &&  ( !c->valid() ) ) ) {
            Codec * g = 0;
            if ( ct->subtype() == "html" )
                g = guessHtmlCodec( body );
            else
                g = guessTextCodec( body );
            UString guessed;
            if ( g )
                guessed = g->toUnicode( body.crlf() );
            if ( !g ) {
                // if we couldn't guess anything, keep what we had if
                // it's valid or explicitly specified, else use
                // unknown-8bit.
                if ( !specified && !c->valid() ) {
                    c = new Unknown8BitCodec;
                    bp->d->text = c->toUnicode( body.crlf() );
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

        ::log( "Bodypart::parseBodypart - checking for invalid codec", Log::Debug );
        if ( specified && c->state() == Codec::Invalid ) {
            // the codec was specified, and the specified codec
            // resulted in an error, but did not abort conversion. we
            // respond by forgetting the error, using the conversion
            // result (probably including one or more U+FFFD) and
            // labelling the message as UTF-8.
            c = new Utf8Codec;
            body = c->fromUnicode( bp->d->text );
        }
        else if ( !specified && c->state() == Codec::Invalid ) {
            // the codec was not specified, and we couldn't find
            // anything. we call it unknown-8bit.
            c = new Unknown8BitCodec;
            bp->d->text = c->toUnicode( body );
        }

        // if we ended up using a 16-bit codec and were using q-p, we
        // need to reevaluate without any trailing CRLF
        if ( e == EString::QP && c->name().startsWith( "UTF-16" ) )
            bp->d->text = c->toUnicode( body.stripCRLF() );

        if ( !c->valid() && bp->d->error.isEmpty() ) {
            bp->d->error = "Could not convert body to Unicode";
            if ( specified ) {
                EString cs;
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
                ::log( "Bodypart::parseBodypart - removeField cte", Log::Debug );
                h->removeField( HeaderField::ContentTransferEncoding );
                cte = 0;
            }
            else if ( cte->encoding() != EString::QP ) {
                cte->setEncoding( EString::QP );
            }
        }
        else if ( qp ) {
            ::log( "Bodypart::parseBodypart - add cte='quoted-printable'", Log::Debug );
            h->add( "Content-Transfer-Encoding", "quoted-printable" );
            cte = h->contentTransferEncoding();
        }
    }
    else {
        ::log( "Bodypart::parseBodypart - content-type is not text, body:" + body, Log::Debug );
        ::log( "Bodypart::parseBodypart - content-type ct->type:" + ct->type(), Log::Debug );
        ::log( "Bodypart::parseBodypart - content-type ct->subtype:" + ct->subtype(), Log::Debug );
        if ( body.needsQP() ) {
            ::log( "Bodypart::parseBodypart - body needs QP", Log::Debug );
        }
        bp->d->data = body;
        if ( ct->type() != "multipart" && ct->type() != "message" ) {
            e = EString::Base64;
            // there may be exceptions. cases where some format really
            // needs another content-transfer-encoding:
            if ( ct->type() == "application" &&
                 ct->subtype().startsWith( "pgp-" ) ) { // hgu: removed:  &&  !body.needsQP() ) {
                ::log( "Bodypart::parseBodypart - 'pgp-' encountered", Log::Debug );
                // seems some PGP things need "Version: 1" unencoded
                e = EString::Binary;
            }
            else if ( ct->type() == "application" &&
                      ct->subtype() == "octet-stream" &&
                      body.contains( "BEGIN PGP MESSAGE" ) ) {
                // mutt cannot handle PGP in base64 (what a crock)
                ::log( "Bodypart::parseBodypart - 'BEGIN PGP MESSAGE' encountered", Log::Debug );
                e = EString::Binary;
            }
            // change c-t-e to match the encoding decided above
            if ( e == EString::Binary ) {
                ::log( "Bodypart::parseBodypart - cte is binary, removeField", Log::Debug );
                h->removeField( HeaderField::ContentTransferEncoding );
                cte = 0;
            }
            else if ( cte ) {
                ::log( "Bodypart::parseBodypart - before setencoding", Log::Debug );
                cte->setEncoding( e );
            }
            else {
                ::log( "Bodypart::parseBodypart - add cte='base64'", Log::Debug );
                h->add( "Content-Transfer-Encoding", "base64" );
                cte = h->contentTransferEncoding();
            }
        }
    }
    ::log( "Bodypart::parseBodypart - before asking if multipart", Log::Debug );

    if ( ct->type() == "multipart" ) {
        ::log( "Bodypart::parseBodypart - will parseMultipart", Log::Debug );
        parseMultipart( start, end, rfc2822,
                        ct->parameter( "boundary" ),
                        ct->subtype() == "digest",
                        bp->children(), bp, false );
    }
    else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // There are sometimes blank lines before the message.
        while ( rfc2822[start] == 13 || rfc2822[start] == 10 )
            start++;
        Message * m = new Message;
        m->setParent( bp );
        m->parse( rfc2822.mid( start, end-start ) );
        List<Bodypart>::Iterator it( m->children() );
        while ( it ) {
            bp->children()->append( it );
            it->setParent( bp );
            ++it;
        }
        bp->setMessage( m );
        body = m->rfc822( false );
    }
    ::log( "Bodypart::parseBodypart - after querying rfc822", Log::Debug );

    bp->d->numBytes = body.length();
    if ( cte )
        body = body.encoded( cte->encoding(), 72 );
    bp->d->numEncodedBytes = body.length();
    if ( bp->d->hasText ||
         ( ct->type() == "message" && ct->subtype() == "rfc822" ) ) {
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

    ::log( "Bodypart::parseBodypart - before simplify header", Log::Debug );
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

EString Bodypart::error() const
{
    return d->error;
}

bool Bodypart::isPgpSigned()
{
    return d->isPgpSigned;
}

void Bodypart::setPgpSigned( bool isSigned )
{
    d->isPgpSigned = isSigned;
}
