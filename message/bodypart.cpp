// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "bodypart.h"

#include "codec.h"
#include "ustring.h"
#include "header.h"
#include "message.h"
#include "mimefields.h"


class BodypartData {
public:
    BodypartData()
        : number( 1 ),
          cte( String::Binary ), parent( 0 ), rfc822( 0 ),
          numBytes( 0 ), numLines( 0 )
    {}

    uint number;

    String::Encoding cte;
    Multipart *parent;
    Message *rfc822;

    uint numBytes;
    uint numLines;

    String data;
    UString text;
};


/*! \class Bodypart bodypart.h

    The Bodypart class models a single MIME body part. It is a subclass
    of Multipart, and an adjunct to Message.

    Every Bodypart has a number(), a contentType(), and an encoding().
    Bodyparts contain text(), data(), or an rfc822() message, based on
    their Content-Type. Each one knows the numBytes() and numLines() of
    data that it contains, and it can present itself asText().

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

Bodypart::Bodypart( uint n, Multipart *p )
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
    pointer in case the Content-Type is the default one.

    The Bodypart cannot find the default alone, since it depends on
    the surrounding type.
*/

ContentType * Bodypart::contentType() const
{
    if ( !d || !header() )
        return 0;
    return header()->contentType();
}


/*! Returns this Bodypart's encoding. */

String::Encoding Bodypart::encoding() const
{
    return d->cte;
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


/*! Returns this Bodypart's content, provided it's a text part. If
    it's not a text part, this function returns an empty string.
*/

UString Bodypart::text() const
{
    return d->text;
}


/*! Sets the text of this Bodypart to \a s. For use only by
    MessageBodyFetcher for now.
*/

void Bodypart::setText( const UString &s )
{
    d->text = s;
}


/*! If this Bodypart is a message/rfc822, this function returns a
    pointer to the subsidiary message. In all other cases, this
    function returns a null pointer.
*/

Message *Bodypart::rfc822() const
{
    return d->rfc822;
}


/*! Sets the subsidiary rfc822() message of this Bodypart to \a m. */

void Bodypart::setRfc822( Message *m )
{
    d->rfc822 = m;
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


/*! Notifies this Bodypart that it contains \a n lines of text().
    The initial value is 0.
*/

void Bodypart::setNumLines( uint n )
{
    d->numLines = n;
}


/*! Returns the number of lines in this body part, as set using
    setNumLines().
*/

uint Bodypart::numLines() const
{
    return d->numLines;
}


/*! Returns the text representation of this Bodypart. */

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
        appendMultipart( r, children(), header() );
    else if ( !d->text.isEmpty() )
        r = c->fromUnicode( d->text );
    else if ( header()->contentType() &&
              header()->contentType()->type() != "text" )
        r = d->data.e64( 72 );
    else
        r = d->data.encode( d->cte, 72 );

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

void Bodypart::parseMultiPart( uint i, uint end,
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
    while ( !last && i < end ) {
        if ( i < end &&
             rfc2822[i] == '-' && rfc2822[i+1] == '-' &&
             ( i == 0 || rfc2822[i-1] == 13 || rfc2822[i-1] == 10 ) &&
             rfc2822[i+2] == divider[0] &&
             rfc2822.mid( i+2, divider.length() ) == divider )
        {
            uint j = i + 2 + divider.length();
            bool l = false;
            if ( rfc2822[j] == '-' && rfc2822[j+1] == '-' ) {
                j += 2;
                l = true;
            }
            while ( rfc2822[j] == ' ' || rfc2822[j] == '\t' )
                j++;
            if ( rfc2822[j] == 13 || rfc2822[j] == 10 ) {
                // finally. we accept that as a boundary line.
                if ( rfc2822[j] == 13 )
                    j++;
                if ( rfc2822[j] == 10 )
                    j++;
                if ( start > 0 ) {
                    Header * h =
                        Message::parseHeader( start, j, rfc2822, Header::Mime );
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

    ContentType * ct = h->contentType();

    String::Encoding e = String::Binary;
    ContentTransferEncoding * cte = h->contentTransferEncoding();
    if ( cte )
        e = cte->encoding();

    Bodypart * bp = new Bodypart;
    bp->setHeader( h );

    String body;
    if ( end > start )
        body = rfc2822.mid( start, end-start ).decode( e );

    if ( !ct || ct->type() == "text" ) {
        Codec * c = 0;
        if ( ct )
            c = Codec::byName( ct->parameter( "charset" ) );
        if ( c )
            ct->removeParameter( "charset" );
        else
            c = new AsciiCodec;

        bp->d->text = c->toUnicode( body );
        if ( !c->valid() && error.isEmpty() )
            error = "Error converting body from " + c->name() + " to Unicode";

        // Is there a better codec for this data?
        if ( ct )
            c = Codec::byString( bp->d->text );
        if ( ct && c->name().lower() != "us-ascii" )
            ct->addParameter( "charset", c->name().lower() );

        String s = c->fromUnicode( bp->d->text );
        h->removeField( HeaderField::ContentTransferEncoding );
        if ( s.needsQP() )
            h->add( "Content-Transfer-Encoding", "quoted-printable" );
        h->simplify();
        bp->d->numBytes = bp->d->text.length();
    }
    else {
        if ( ct->type() != "multipart" && ct->type() != "message" ) {
            h->removeField( HeaderField::ContentTransferEncoding );
            h->add( "Content-Transfer-Encoding", "base64" );
            h->simplify();
        }
        bp->d->data = body;
        bp->d->numBytes = body.length();
    }

    if ( !bp->d->text.isEmpty() ) {
        uint i = 0;
        while ( i < bp->d->text.length() ) {
            if ( bp->d->text[i] == '\n' )
                bp->d->numLines++;
            i++;
        }
    }

    if ( !ct ) {
        ;
    }
    else if ( ct->type() == "multipart" ) {
        parseMultiPart( start, end, rfc2822,
                        ct->parameter( "boundary" ),
                        ct->subtype() == "digest",
                        bp->children(), bp, error );
    }
    else if ( ct->type() == "message" && ct->subtype() == "rfc822" ) {
        // message/rfc822
        Message * m = new Message( rfc2822.mid( start, end ) );
        List<Bodypart>::Iterator it( m->children()->first() );
        while ( it ) {
            bp->children()->append( it );
            it->setParent( bp );
            ++it;
        }
        bp->d->rfc822 = m;
    }

    return bp;
}
