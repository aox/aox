// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mimefields.h"

#include "field.h"
#include "string.h"
#include "parser.h"
#include "list.h"


class MimeFieldData
{
public:
    MimeFieldData() : valid( false ) {}

    struct Parameter {
        bool operator<=( const Parameter & other ) const {
            return name <= other.name;
        }
        String name;
        String value;
    };
    SortedList<Parameter> parameters;
    bool valid;
};


/*! \class MimeField mimefields.h
    The MimeField class models the typical characteristics of the
    MIME-defined header fields.

    Said typical characteristics are, well, singular: Is the ;a=b;c=d
    series of arguments at the end.
*/


/*!  Constructs an empty MimeField object. */

MimeField::MimeField()
    : d( new MimeFieldData )
{
}


/*! Parses \a p, which is expected to refer to a string whose next
    characters form the RFC 2045 production '*(";"parameter)'.
*/

void MimeField::parse( Parser822 * p )
{
    p->whitespace();

    while ( p->next() == ';' ) {
        String n;
        p->step();
        p->whitespace();
        n = p->mimeToken().lower();
        p->whitespace();
        if ( n.isEmpty() || p->next() != '=' )
            return;

        p->step();
        String v = p->mimeValue();
        addParameter( n, v );
        p->whitespace();
    }

    if ( p->atEnd() )
        d->valid = true;
}


/*! Allocates and returns a list of parameters. The list is on the
    current arena, and each item is lowercased.
*/

StringList * MimeField::parameterList() const
{
    StringList * l = new StringList;
    List<MimeFieldData::Parameter>::Iterator it( d->parameters.first() );
    while ( it ) {
        l->append( new String( it->name ) );
        ++it;
    }
    return l;
}


/*! Returns the argument named \a n. The comparison is case
    insensitive. If there is no such item, parameter() returns an
    empty string.
*/

String MimeField::parameter( const String & n ) const
{
    String s = n.lower();
    List<MimeFieldData::Parameter>::Iterator it( d->parameters.first() );
    while ( it && s != it->name )
        ++it;
    if ( it )
        return it->value;
    return "";
}


/*! Removes the parameter named \a n, or does nothing if there is no
    such parameter.
*/

void MimeField::removeParameter( const String & n )
{
    List<MimeFieldData::Parameter>::Iterator it( d->parameters.first() );
    while ( it && n != it->name )
        ++it;
    if ( it )
        d->parameters.take( it );
}


/*! Adds a parameter named \a n with value \a v, replacing any
    previous setting.
*/

void MimeField::addParameter( const String & n, const String & v )
{
    removeParameter( n );
    MimeFieldData::Parameter *pm = new MimeFieldData::Parameter;
    pm->name = n;
    pm->value = v;
    d->parameters.insert( pm );
}


/*! Returns true if this object has been completely parsed and found
    to be valid, and false if not.
*/

bool MimeField::valid() const
{
    return d->valid;
}


/*! Notifies this object that it's valid if \a v is true, and invalid
    if it's false. The object simply believes what it's told.
*/

void MimeField::setValid( bool v )
{
    d->valid = v;
}



/*! \class ContentType mimefields.h
    Parses Content-Type header fields.

    The Content-Type field is defined in RFC 2045, §5. It contains the
    media type of an entity body, along with any auxiliary information
    required to describe the type.
*/


/*! Constructs a ContentType object with the value \a s. */

ContentType::ContentType( const String &s )
{
    Parser822 p( s );

    // Tolerate elm's "Content-Type: text".
    if ( s.simplified() == "text" ) {
        setValid( true );
        t = "text";
        st = "plain";
        return;
    }

    // Parse: type "/" subtype *( ";" attribute = value )
    // We treat tokens as atoms, but they really aren't.

    if ( ( t = p.mimeToken().lower() ) != "" && p.character() == '/' &&
         ( st = p.mimeToken().lower() ) != "" )
        parse( &p );

    if ( t == "multipart" && valid() && parameter( "boundary" ).isEmpty() )
        setValid( false );
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
    Parses Content-Transfer-Encoding header fields.

    The Content-Transfer-Encoding field is defined in RFC 2045,
    section 6. If present, it specifies the transfer encoding applied
    to a body-part. If absent, the body-part is assumed to be 7bit.

    We don't differentiate between 7bit, 8bit and binary; all are
    treated the same way.
*/


/*! Creates a ContentTransferEncoding object with the value \a s. */

ContentTransferEncoding::ContentTransferEncoding( const String &s )
{
    Parser822 p( s );

    String t = p.mimeToken().lower();
    p.comment();

    setValid( false );

    if ( t == "7bit" || t == "8bit" || t == "binary" )
        e = String::Binary;
    else if ( t == "quoted-printable" )
        e = String::QP;
    else if ( t == "base64" )
        e = String::Base64;
    else
        return;

    if ( !p.atEnd() )
        return;

    setValid( true );
}


/*! Sets the encoding of this ContentTransferEncoding object to \a en,
    and updates the contents of \a hf.

    This is a special hack for use by Bodypart::parseBodypart() in an
    attempt to preserve field order.
*/

void ContentTransferEncoding::setEncoding( String::Encoding en,
                                           HeaderField *hf )
{
    e = en;

    String r;
    switch ( e ) {
    case String::Binary:
        r = "7bit";
        break;
    case String::QP:
        r = "quoted-printable";
        break;
    case String::Base64:
        r = "base64";
        break;
    }
    hf->setValue( r );
    hf->setData( r );
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


/*! Creates a ContentDisposition object with the value \a s. */

ContentDisposition::ContentDisposition( const String &s )
{
    Parser822 p( s );
    String t;

    if ( ( t = p.mimeToken().lower() ) != "" )
        parse( &p );

    if ( t == "inline" )
        d = Inline;
    else // if ( t == "attachment" )
        d = Attachment;
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


/*! Creates a ContentLanguage object with the value \a s. */

ContentLanguage::ContentLanguage( const String &s )
{
    Parser822 p( s );
    setValid( false );

    do {
        // We're not going to bother trying to validate language tags.
        p.comment();
        String t = p.mimeToken();
        if ( t != "" )
            l.append( t );
        p.comment();
    } while ( p.character() == ',' );

    if ( !p.atEnd() || l.count() == 0 )
        return;

    setValid( true );
}


/*! Returns the list of language tags. */

const StringList *ContentLanguage::languages() const
{
    return &l;
}


