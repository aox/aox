// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "field.h"

#include "date.h"
#include "ustring.h"
#include "address.h"
#include "datefield.h"
#include "mimefields.h"
#include "addressfield.h"
#include "parser.h"
#include "utf.h"


static struct {
    const char * name;
    HeaderField::Type type;
} fieldNames[] = {
    { "From", HeaderField::From },
    { "Resent-From", HeaderField::ResentFrom },
    { "Sender", HeaderField::Sender },
    { "Resent-Sender", HeaderField::ResentSender },
    { "Return-Path", HeaderField::ReturnPath },
    { "Reply-To", HeaderField::ReplyTo },
    { "To", HeaderField::To },
    { "Cc", HeaderField::Cc },
    { "Bcc", HeaderField::Bcc },
    { "Resent-To", HeaderField::ResentTo },
    { "Resent-Cc", HeaderField::ResentCc },
    { "Resent-Bcc", HeaderField::ResentBcc },
    { "Message-Id", HeaderField::MessageId },
    { "Resent-Message-Id", HeaderField::ResentMessageId },
    { "In-Reply-To", HeaderField::InReplyTo },
    { "References", HeaderField::References },
    { "Date", HeaderField::Date },
    { "Orig-Date", HeaderField::OrigDate },
    { "Resent-Date", HeaderField::ResentDate },
    { "Subject", HeaderField::Subject },
    { "Comments", HeaderField::Comments },
    { "Keywords", HeaderField::Keywords },
    { "Content-Type", HeaderField::ContentType },
    { "Content-Transfer-Encoding", HeaderField::ContentTransferEncoding },
    { "Content-Disposition", HeaderField::ContentDisposition },
    { "Content-Description", HeaderField::ContentDescription },
    { "Content-Language", HeaderField::ContentLanguage },
    { "Content-Location", HeaderField::ContentLocation },
    { "Content-Md5", HeaderField::ContentMd5 },
    { "Content-Id", HeaderField::ContentId },
    { "Mime-Version", HeaderField::MimeVersion },
    { "Received", HeaderField::Received },
    { 0, HeaderField::Other },
};


class HeaderFieldData {
public:
    HeaderFieldData()
        : type( HeaderField::Other )
    {}

    HeaderField::Type type;
    String name, data, value, string, error;
};


/*! \class HeaderField field.h
    This class models a single RFC 822 header field (e.g. From).

    This class is responsible for parsing and verifying header fields.
    Each field has a type(), name(), and value(). It is valid() if no
    error() was recorded during parsing by the various functions that
    parse() field values, e.g. parseText()).

    Users may obtain HeaderField objects only via create().
*/

/*! This static function returns a pointer to a new HeaderField object
    that represents the given field \a name (case-insensitive) and its
    \a value (which is parsed appropriately).
*/

HeaderField *HeaderField::create( const String &name, const String &value )
{
    int i = 0;
    String n = name.headerCased();
    while ( fieldNames[i].name && n != fieldNames[i].name )
        i++;

    HeaderField::Type t = fieldNames[i].type;
    HeaderField *hf;

    switch ( t ) {
    default:
        hf = new HeaderField( fieldNames[i].type );
        break;

    case From:
    case ResentFrom:
    case Sender:
    case ResentSender:
    case ReturnPath:
    case ReplyTo:
    case To:
    case Cc:
    case Bcc:
    case ResentTo:
    case ResentCc:
    case ResentBcc:
    case MessageId:
    case ResentMessageId:
    case References:
        hf = new AddressField( t );
        break;

    case Date:
    case OrigDate:
    case ResentDate:
        hf = new DateField( t );
        break;

    case ContentType:
        hf = new ::ContentType;
        break;

    case ContentTransferEncoding:
        hf = new ::ContentTransferEncoding;
        break;

    case ContentDisposition:
        hf = new ::ContentDisposition;
        break;

    case ContentLanguage:
        hf = new ::ContentLanguage;
        break;
    }

    hf->setName( n );
    hf->setString( value );
    hf->parse();

    return hf;
}


/*! Constructs a HeaderField of type \a t. */

HeaderField::HeaderField( HeaderField::Type t )
    : d( new HeaderFieldData )
{
    d->type = t;
}


/*! Returns the type of this header field, as set by the constructor
    based on the name(). Unknown fields have type HeaderField::Other.
*/

HeaderField::Type HeaderField::type() const
{
    return d->type;
}


/*! Returns the canonical name of this header field. */

String HeaderField::name() const
{
    return d->name;
}


/*! Sets the name of this HeaderField to \a n. */

void HeaderField::setName( const String &n )
{
    d->name = n;
}


/*! Returns the unparsed contents of this HeaderField. This is the
    string we extract from mail to be parsed.
*/

String HeaderField::string() const
{
    return d->string;
}


/*! Sets the unparsed contents of this HeaderField to \a s. */

void HeaderField::setString( const String &s )
{
    d->string = s;
}


/*! Returns the canonical, folded (and, if required, RFC 2047-encoded)
    version of the contents of this HeaderField. This is the string we
    can use to form headers that are handed out to clients.
*/

String HeaderField::value() const
{
    return d->value;
}


/*! Sets the value of this HeaderField to \a s. */

void HeaderField::setValue( const String &s )
{
    d->value = s;
}


/*! Returns the canonical, unfolded, UTF-8 encoded version of value().
    This is the value we store in the database.
*/

String HeaderField::data() const
{
    return d->data;
}


/*! Sets the data of this HeaderField to \a s. */

void HeaderField::setData( const String &s )
{
    d->data = s;
}


/*! Returns true if this header field is valid (or unparsed, as is the
    case for all unknown fields), and false if an error was detected
    during parsing.
*/

bool HeaderField::valid() const
{
    return d->error.isEmpty();
}


/*! Returns a suitable error message if this header field has a known
    parse error, and an empty string if the field is valid() or -- as
    is the case for all unknown fields -- not parsed.
*/

String HeaderField::error() const
{
    return d->error;
}


/*! Records the error text \a s encountered during parsing. */

void HeaderField::setError( const String &s )
{
    d->error = s;
}


/*! This function decides how to parse this header field based on the
    type() assigned by the constructor. It leaves the actual parsing
    to functions like parseText().
*/

void HeaderField::parse()
{
    // XXX: We don't handle folding or RFC 2047 encoding properly yet.
    d->data = d->value = d->string;

    switch ( d->type ) {
    case From:
    case ResentFrom:
    case Sender:
    case ReturnPath:
    case ResentSender:
    case To:
    case Cc:
    case Bcc:
    case ReplyTo:
    case ResentTo:
    case ResentCc:
    case ResentBcc:
    case MessageId:
    case ContentId:
    case ResentMessageId:
    case References:
    case Date:
    case OrigDate:
    case ResentDate:
    case ContentType:
    case ContentTransferEncoding:
    case ContentDisposition:
    case ContentLanguage:
        // These should be handled by their own parse().
        break;

    case Subject:
    case Comments:
        // parseText();
        break;

    case MimeVersion:
        parseMimeVersion();
        break;

    case ContentLocation:
        parseContentLocation();
        break;

    case InReplyTo:
    case Keywords:
    case Received:
    case ContentMd5:
    case ContentDescription:
        // no action necessary
        break;

    case Other:
        // no action possible
        break;
    }
}


/*! Parses the *text production, as modified to include encoded-words by
    RFC 2047. This is used to parse the Subject and Comments fields.
*/

void HeaderField::parseText()
{
    Utf8Codec u;
    Parser822 p( value() );
    d->data = u.fromUnicode( p.text() );
}


/*! Parses the Mime-Version syntax and records the first problem
    found.

    Only version 1.0 is accepted. Since some message generators
    incorrectly send comments, this parser accepts them.
*/

void HeaderField::parseMimeVersion()
{
    Parser822 p( d->value );
    p.comment();
    String v = p.dotAtom();
    p.comment();
    if ( v != "1.0" || !p.atEnd() )
        setError( "Could not parse '" + v.simplified() + "'" );
}


/*! Parses the Content-Location header field and records the first
    problem found.
*/

void HeaderField::parseContentLocation()
{
    Parser822 p( d->value );
    String s;
    char c;

    // We pretend a URI is just something without spaces in it.
    // Why the HELL couldn't this have been quoted?
    p.comment();
    while ( ( c = p.character() ) != '\0' && c != ' ' && c != '\t' )
        s.append( c );
    p.comment();

    if ( !p.atEnd() )
        setError( "Junk at end of '" + value().simplified() + "'" );
    d->value = s;
}


/*! Returns the name corresponding to the field type \a t, or 0 if there
    is no such field.
*/

const char *HeaderField::fieldName( HeaderField::Type t )
{
    uint i = 0;
    while ( fieldNames[i].name && fieldNames[i].type != t )
        i++;
    return fieldNames[i].name;
}
