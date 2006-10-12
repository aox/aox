// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mimefields.h"

#include "field.h"
#include "string.h"
#include "parser.h"
#include "list.h"


class MimeFieldData
    : public Garbage
{
public:
    struct Parameter
        : public Garbage
    {
        String name;
        String value;
    };
    List< Parameter > parameters;
};


/*! \class MimeField mimefields.h
    This is a base class for the complex MIME header fields. It inherits
    from HeaderField, and provides methods to parse and maintain a list
    of MIME parameters.
*/


/*! Constructs a new MimeField of type \a t. Only for use by subclasses.
    Users should obtain MimeFields from HeaderField::create().
*/

MimeField::MimeField( HeaderField::Type t )
    : HeaderField( t ),
      d( new MimeFieldData )
{
}


/*! Returns a pointer to a list of the parameters for this MimeField.
    This is never a null pointer. */

StringList *MimeField::parameters() const
{
    StringList *l = new StringList;
    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it ) {
        l->append( new String( it->name ) );
        ++it;
    }
    return l;
}


/*! Returns the canonical string representation of this MimeField's
    parameters() (including the leading ";"), or an empty string if
    there are no parameters.
*/

String MimeField::parameterString() const
{
    String s;
    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it ) {
        s.append( "; " );
        s.append( it->name );
        s.append( "=" );

        String v = it->value;
        if ( v.boring( String::MIME ) )
            s.append( v );
        else
            s.append( v.quoted() );
        ++it;
    }

    return s;
}


/*! Returns the value of the parameter named \a n (ignoring the case of
    the name). If there is no such parameter, this function returns an
    empty string.
*/

String MimeField::parameter( const String &n ) const
{
    String s = n.lower();
    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it && s != it->name )
        ++it;
    if ( it )
        return it->value;
    return "";
}


/*! Adds a parameter named \a n with value \a v, replacing any
    previous setting.
*/

void MimeField::addParameter( const String &n, const String &v )
{
    String s = n.lower();
    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it && s != it->name )
        ++it;
    if ( it ) {
        it->value = v;
    }
    else {
        MimeFieldData::Parameter *pm = new MimeFieldData::Parameter;
        pm->name = n;
        pm->value = v;
        d->parameters.append( pm );
    }
}


/*! Removes the parameter named \a n (without regard to case), or does
    nothing if there is no such parameter.
*/

void MimeField::removeParameter( const String &n )
{
    String s = n.lower();
    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it && s != it->name )
        ++it;
    if ( it )
        d->parameters.take( it );
}


/*! Parses \a p, which is expected to refer to a string whose next
    characters form the RFC 2045 production '*(";"parameter)'.
*/

void MimeField::parseParameters( Parser822 *p )
{
    p->whitespace();

    while ( p->next() == ';' ) {
        while ( p->next() == ';' )
            p->step();
        p->whitespace();
        String n = p->mimeToken().lower();
        p->comment();

        if ( n.isEmpty() ) {
            if ( p->atEnd() )
                return; // for 'Content-Type: text/html;'
            setError( "Empty parameter" );
            return;
        }
        else if ( p->next() != '=' ) {
            setError( "Bad parameter: '" + n.simplified() + "'" );
            return;
        }

        p->step();
        String v = p->mimeValue();
        addParameter( n, v );
        p->comment();
    }
}


String MimeField::value()
{
    String s = HeaderField::data();
    s.append( parameterString() );
    return wrap( s );
}


String MimeField::data()
{
    String s = HeaderField::data();
    s.append( parameterString() );
    return s;
}



/*! \class ContentType mimefields.h

    The Content-Type field is defined in RFC 2045 section 5. It contains the
    media type of an entity body, along with any auxiliary information
    required to describe the type.
*/


/*! Constructs a new ContentType object. */

ContentType::ContentType()
    : MimeField( HeaderField::ContentType )
{
}


/*! This function exists to workaround an incorrect gcc warning about
    ContentType having virtual functions (it doesn't), but not a
    virtual destructor.
*/

ContentType::~ContentType()
{
}


void ContentType::parse( const String &s )
{
    Parser822 p( s );
    p.whitespace();

    if ( p.atEnd() ) {
        t = "text";
        st = "plain";
    }
    else {
        t = p.mimeToken().lower();
        if ( p.atEnd() ) {
            if ( s == "text" ) {
                t = "text"; // elm? mailtool? someone does this, anyway.
                st = "plain";
            }
            // the remainder is from RFC 1049
            else if ( s == "postscript" ) {
                t = "application";
                st = "postscript";
            }
            else if ( s == "postscript" ) {
                t = "application";
                st = "postscript";
            }
            else if ( s == "sgml" ) {
                t = "text";
                st = "sgml";
            }
            else if ( s == "tex" ) {
                t = "application";
                st = "x-tex";
            }
            else if ( s == "troff" ) {
                t = "application";
                st = "x-troff";
            }
            else if ( s == "dvi" ) {
                t = "application";
                st = "x-dvi";
            }
            else if ( s.startsWith( "x-" ) ) {
                st = "x-rfc1049-" + s;
                t = "application";
            }
            else {
                // scribe and undefined types
                setError( "Invalid Content-Type: '" + s + "'" );
            }
        }
        else {
            if ( p.next() == '/' ) {
                // eek. this makes mime look like the special case.
                p.step();
                st = p.mimeToken().lower();
            }
            else if ( t == "binary" ) {
                t = "application";
                st = "octet-stream";
            }
            parseParameters( &p );
        }
    }

    if ( t.isEmpty() || st.isEmpty() )
        setError( "Both type and subtype must be nonempty: '" + s + "'" );

    if ( valid() && t == "multipart" && parameter( "boundary" ).isEmpty() )
        setError( "Multipart entities must have a boundary parameter." );

    if ( valid() && !p.atEnd() && parameter( "charset" ).isEmpty() &&
         s.mid( p.index() ).lower().contains( "charset" ) )
        setError( "Parse error at position " + fn( p.index() ) +
                  ", before charset" );

    String v = t + "/" + st;
    setData( v );
}


/*! Returns the media type. */

String ContentType::type() const
{
    return t;
}


/*! Returns the media subtype. */

String ContentType::subtype() const
{
    return st;
}



/*! \class ContentTransferEncoding mimefields.h

    The Content-Transfer-Encoding field is defined in RFC 2045,
    section 6. If present, it specifies the transfer encoding applied
    to a body-part. If absent, the body-part is assumed to be 7bit.

    We don't differentiate between 7bit, 8bit and binary; all are
    treated the same way.
*/


/*! Constructs a new ContentTransferEncoding object. */

ContentTransferEncoding::ContentTransferEncoding()
    : MimeField( HeaderField::ContentTransferEncoding )
{
}


void ContentTransferEncoding::parse( const String &s )
{
    Parser822 p( s );

    String t = p.mimeToken().lower();
    p.comment();

    if ( t == "7bit" || t == "8bit" || t == "8bits" || t == "binary" ||
         t == "unknown" )
        e = String::Binary;
    else if ( t == "quoted-printable" )
        e = String::QP;
    else if ( t == "base64" )
        e = String::Base64;
    else if ( t == "x-uuencode" || t == "uuencode" )
        e = String::Uuencode;
    else
        setError( "Invalid c-t-e value: '" + t + "'" );

    setData( t );
}


/*! Sets the encoding of this ContentTransferEncoding object to \a en.
    This is a special hack for use by Bodypart::parseBodypart() in an
    attempt to preserve field order.
*/

void ContentTransferEncoding::setEncoding( String::Encoding en )
{
    e = en;

    String s;
    switch ( e ) {
    case String::Binary:
        s = "7bit";
        break;
    case String::QP:
        s = "quoted-printable";
        break;
    case String::Base64:
        s = "base64";
        break;
    case String::Uuencode:
        s = "x-uuencode";
        break;
    }
    setData( s );
}


/*! Returns the encoding, or Binary in case of error. */

String::Encoding ContentTransferEncoding::encoding() const
{
    return e;
}



/*! \class ContentDisposition mimefields.h
    Parses Content-Disposition header fields (RFC 2183).

    The Content-Disposition header field is used to convey presentation
    information for a MIME entity. The two values initially defined are
    "inline" and "attachment".
*/

/*! Constructs a new ContentDisposition object. */

ContentDisposition::ContentDisposition()
    : MimeField( HeaderField::ContentDisposition )
{
}


/*! Parses a Content-Disposition field in \a s. */

void ContentDisposition::parse( const String &s )
{
    Parser822 p( s );

    String t;
    if ( ( t = p.mimeToken().lower() ) != "" ) {
        if ( t == "inline" )
            d = Inline;
        else // if ( t == "attachment" )
            d = Attachment;
        parseParameters( &p );
        setData( t );
        return;
    }

    setError( "Invalid disposition: '" + s.simplified() + "'" );
}


/*! Returns the disposition. */

ContentDisposition::Disposition ContentDisposition::disposition() const
{
    return d;
}



/*! \class ContentLanguage mimefields.h
    Parses Content-Language header fields (RFC 3282)

    The Content-Language header field indicates the language of the MIME
    entity it is associated with. Its value is a Language-Tag or list as
    defined in RFC 3066.
*/


/*! Creates a new ContentLanguage object. */

ContentLanguage::ContentLanguage()
    : MimeField( HeaderField::ContentLanguage )
{
}


/*! This function exists to workaround an incorrect gcc warning about
    ContentLanguage having virtual functions (it doesn't), but not a
    virtual destructor.
*/

ContentLanguage::~ContentLanguage()
{
}


/*! Parses a Content-Language field in \a s. */

void ContentLanguage::parse( const String &s )
{
    Parser822 p( s );

    do {
        // We're not going to bother trying to validate language tags.
        p.comment();
        String t = p.mimeToken();
        if ( t != "" )
            l.append( t );
        p.comment();
    } while ( p.character() == ',' );

    if ( !p.atEnd() || l.count() == 0 )
        setError( "Unparseable value: '" + s.simplified() + "'" );

    setData( s );
}


/*! Returns the list of language tags. */

const StringList *ContentLanguage::languages() const
{
    return &l;
}
