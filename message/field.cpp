// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "field.h"

#include "date.h"
#include "ustring.h"
#include "address.h"
#include "mimefields.h"
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
        : type( HeaderField::Other ),
          date( 0 ), addresses( 0 )
    {}

    HeaderField::Type type;

    String name;
    String string;

    String data;
    String value;

    ::Date *date;
    List< ::Address > *addresses;
    ::ContentType *contentType;
    ::ContentTransferEncoding *cte;
    ::ContentDisposition *cd;
    ::ContentLanguage *cl;

    String error;
};


/*! \class HeaderField field.h
    This class models a single RFC 822 header field (e.g. From).

    This class is responsible for parsing and verifying header fields.
    Each field has a type(), name(), and value(). It is valid() if no
    error() was recorded during parsing by the various functions that
    parse() field values, e.g. parseMailbox()).

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

    HeaderField *hf = new HeaderField( fieldNames[i].type );

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


/*! Sets the name of this HeaderField to \a n. */

void HeaderField::setName( const String &n )
{
    d->name = n;
}


/*! Sets the data of this HeaderField to \a s. */

void HeaderField::setData( const String &s )
{
    d->data = s;
}


/*! Sets the value of this HeaderField to \a s. */

void HeaderField::setValue( const String &s )
{
    d->value = s;
}


/*! Records the error text \a s encountered during parsing. */

void HeaderField::setError( const String &s )
{
    d->error = s;
}


/*! Sets the unparsed contents of this HeaderField to \a s. */

void HeaderField::setString( const String &s )
{
    d->string = s;
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


/*! Returns the canonical, unfolded, UTF-8 encoded version of value().
    This is the value we store in the database.
*/

String HeaderField::data() const
{
    return d->data;
}


/*! Returns the canonical, folded (and, if required, RFC 2047-encoded)
    version of the contents of this HeaderField. This is the string we
    can use to form headers that are handed out to clients.
*/

String HeaderField::value() const
{
    return d->value;
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


/*! Returns a pointer to the Date value of this header field, or 0 if
    this is not a Date field.
*/

Date *HeaderField::date() const
{
    return d->date;
}


/*! Returns a pointer to the list of addresses in this header field, or
    0 if this is not a field that is known to contain addresses.
*/

List< Address > *HeaderField::addresses() const
{
    return d->addresses;
}


/*! Returns a pointer to the ContentType object contained in this header
    field.

    (This function will go away once MimeField inherits HeaderField.)
*/

ContentType *HeaderField::contentType() const
{
    return d->contentType;
}


/*! Returns a pointer to the ContentTransferEncoding object contained in
    this header field.

    (This function will go away once MimeField inherits HeaderField.)
*/

ContentTransferEncoding *HeaderField::contentTransferEncoding() const
{
    return d->cte;
}


/*! Returns a pointer to the ContentDisposition object contained in this
    header field.

    (This function will go away once MimeField inherits HeaderField.)
*/

ContentDisposition *HeaderField::contentDisposition() const
{
    return d->cd;
}


/*! Returns a pointer to the ContentLanguage object contained in this
    header field.

    (This function will go away once MimeField inherits HeaderField.)
*/

ContentLanguage *HeaderField::contentLanguage() const
{
    return d->cl;
}


/*! This private function decides how to parse this header field based
    on the type() assigned by the constructor. It calls an appropriate
    function to do the actual parsing (e.g., parseMailbox()).
*/

void HeaderField::parse()
{
    // XXX: We don't handle folding or RFC 2047 encoding properly yet.
    d->data = d->value = d->string;

    switch ( d->type ) {
    case HeaderField::Sender:
    case HeaderField::ReturnPath:
    case HeaderField::ResentSender:
        parseMailbox();
        break;

    case HeaderField::From:
    case HeaderField::ResentFrom:
        parseMailboxList();
        break;

    case HeaderField::To:
    case HeaderField::Cc:
    case HeaderField::Bcc:
    case HeaderField::ReplyTo:
    case HeaderField::ResentTo:
    case HeaderField::ResentCc:
    case HeaderField::ResentBcc:
        parseAddressList();
        break;

    case HeaderField::MessageId:
    case HeaderField::ContentId:
    case HeaderField::ResentMessageId:
        parseMessageId();
        break;

    case HeaderField::References:
        parseReferences();
        break;

    case HeaderField::Date:
    case HeaderField::OrigDate:
    case HeaderField::ResentDate:
        parseDate();
        break;

    case HeaderField::Subject:
    case HeaderField::Comments:
        // parseText();
        break;

    case HeaderField::InReplyTo:
    case HeaderField::Keywords:
    case HeaderField::Received:
    case HeaderField::ContentMd5:
    case HeaderField::ContentDescription:
        // no action necessary
        break;

    case HeaderField::MimeVersion:
        parseMimeVersion();
        break;

    case HeaderField::ContentType:
        parseContentType();
        break;

    case HeaderField::ContentTransferEncoding:
        parseContentTransferEncoding();
        break;

    case HeaderField::ContentDisposition:
        parseContentDisposition();
        break;

    case HeaderField::ContentLanguage:
        parseContentLanguage();
        break;

    case HeaderField::ContentLocation:
        parseContentLocation();
        break;

    case HeaderField::Other:
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


/*! Parses the RFC 2822 address-list production and records the first
    problem found.
*/

void HeaderField::parseAddressList()
{
    AddressParser ap( value() );
    d->addresses = ap.addresses();
    d->error = ap.error();
}


/*! Parses the RFC 2822 mailbox-list production and records the first
    problem found.
*/

void HeaderField::parseMailboxList()
{
    parseAddressList();

    // A mailbox-list is an address-list where groups aren't allowed.
    List< Address >::Iterator it( d->addresses->first() );
    while ( it && d->error.isEmpty() ) {
        if ( it->localpart().isEmpty() || it->domain().isEmpty() )
            d->error = "Invalid mailbox: '" + it->toString() + "'";
        ++it;
    }
}


/*! Parses the RFC 2822 mailbox production and records the first
    problem found.
*/

void HeaderField::parseMailbox()
{
    parseMailboxList();

    // A mailbox in our world is just a mailbox-list with one entry.
    if ( d->error.isEmpty() && d->addresses->count() > 1 )
        setError( "Only one address is allowed" );
}


/*! Parses the contents of an RFC 2822 references field. This is
    nominally 1*msg-id, but in practice we need to be a little more
    flexible. Overlooks common problems and records the first serious
    problems found.
*/

void HeaderField::parseReferences()
{
    AddressParser *ap = AddressParser::references( value() );
    d->addresses = ap->addresses();
    setError( ap->error() );
}


/*! Parses the RFC 2822 msg-id production and records the first
    problem found.
*/

void HeaderField::parseMessageId()
{
    parseReferences();

    if ( d->error.isEmpty() && d->addresses->count() > 1 )
        setError( "Only one message-id is allowed" );
}


/*! Parses the RFC 2822 date production and records the first problem
    found.
*/

void HeaderField::parseDate()
{
    d->date = new ::Date;
    d->date->setRfc822( value() );
    if ( !d->date->valid() )
        setError( "Could not parse '" + value().simplified() + "'" );
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


/*! Parses the Content-Type header field and records the first problem
    found.
*/

void HeaderField::parseContentType()
{
    d->contentType = new ::ContentType( value() );
    if ( !d->contentType->valid() )
        setError( "Could not parse '" + value().simplified() + "'" );
}


/*! Parses the Content-Transfer-Encoding header field and records the
    first problem found.
*/

void HeaderField::parseContentTransferEncoding()
{
    d->cte = new ::ContentTransferEncoding( value() );
    if ( !d->cte->valid() )
        setError( "Could not parse '" + value().simplified() + "'" );
}


/*! Parses the Content-Disposition header field and records the first
    problem found.
*/

void HeaderField::parseContentDisposition()
{
    d->cd = new ::ContentDisposition( value() );
    if ( !d->cd->valid() )
        setError( "Could not parse '" + value().simplified() + "'" );
}


/*! Parses the Content-Language header field and records the first
    problem found.
*/

void HeaderField::parseContentLanguage()
{
    d->cl = new ::ContentLanguage( value() );
    if ( !d->cl->valid() )
        setError( "Could not parse '" + value().simplified() + "'" );
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


