// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "field.h"

#include "date.h"
#include "ustring.h"
#include "address.h"
#include "datefield.h"
#include "mimefields.h"
#include "listidfield.h"
#include "addressfield.h"
#include "ustringlist.h"
#include "stringlist.h"
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
    { "Content-Base", HeaderField::ContentBase },
    { "Content-Md5", HeaderField::ContentMd5 },
    { "Content-Id", HeaderField::ContentId },
    { "Mime-Version", HeaderField::MimeVersion },
    { "Received", HeaderField::Received },
    { 0, HeaderField::Other },
};


class HeaderFieldData
    : public Garbage
{
public:
    HeaderFieldData() : type( HeaderField::Other ), position( (uint)-1 ) {}

    HeaderField::Type type;
    String name;
    UString value;
    String unparsed;
    String error;
    uint position;
};


/*! \class HeaderField field.h
    This class models a single RFC 822 header field (e.g. From).

    This class is responsible for parsing and verifying header fields.
    Each field has a type(), name(), and value(). It is valid() if no
    error() was recorded during parsing by the various functions that
    parse() field values, e.g. parseText()).

    Users may obtain HeaderField objects only via create().
*/


/*! This private function is used by create() and assemble() to create a
    HeaderField object of a type appropriate to the given \a name.
*/

HeaderField *HeaderField::fieldNamed( const String &name )
{
    int i = 0;
    String n = name.headerCased();
    while ( fieldNames[i].name && n != fieldNames[i].name )
        i++;

    HeaderField::Type t = fieldNames[i].type;
    HeaderField * hf = 0;

    switch ( t ) {
    case InReplyTo:
    case Subject:
    case Comments:
    case Keywords:
    case ContentDescription:
    case MimeVersion:
    case Received:
    case ContentLocation:
    case ContentBase:
    case ContentMd5:
    case Other:
        if ( n == "List-Id" )
            hf = new ListIdField;
        else
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
    case ContentId:
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
    return hf;
}


/*! This static function returns a pointer to a new HeaderField object
    that represents the given field \a name (case-insensitive) and its
    \a value (which is parsed appropriately). Neither \a name nor
    value may contain the separating ':'.

    This function is for use by the message parser.
*/

HeaderField *HeaderField::create( const String &name,
                                  const String &value )
{
    HeaderField *hf = fieldNamed( name );
    hf->parse( value );
    return hf;
}


/*! This static function returns a pointer to a new HeaderField object
    that represents the given field \a name (case-insensitive) and the
    field \a data retrieved from the database.

    This function is for use by the message fetcher.
*/

HeaderField *HeaderField::assemble( const String &name,
                                    const UString &data )
{
    HeaderField *hf = fieldNamed( name );
    // XXX HACK HACK HACK XXX
    // in the case of the mime fields, we store the RFC822 form, and
    // need to reparse when we fetch the blah from the database.
    if ( hf->type() == ContentType ||
         hf->type() == ContentTransferEncoding ||
         hf->type() == ContentLanguage ||
         hf->type() == ContentDisposition )
        hf->parse( data.utf8() );
    else
        hf->setValue( data );
    return hf;
}


/*! Constructs a HeaderField of type \a t. */

HeaderField::HeaderField( HeaderField::Type t )
    : d( new HeaderFieldData )
{
    d->type = t;
}


/*! Exists only to avoid compiler warnings. */

HeaderField::~HeaderField()
{
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
    if ( d->type != Other )
        return fieldName( d->type );
    return d->name;
}


/*! Sets the name of this HeaderField to \a n. */

void HeaderField::setName( const String &n )
{
    d->name = n;
}


/*! Returns the RFC 2822 representation of this header field, with its
    contents properly folded and, if necessary, RFC 2047 encoded. This
    is a string we can hand out to clients.
*/

String HeaderField::rfc822() const
{
    if ( d->type == Subject ||
         d->type == Comments ||
         d->type == ContentDescription )
        return wrap( encodeText( d->value ) );

    if ( d->type == Other )
        return encodeText( d->value );

    // We assume that, for most fields, we can use the database
    // representation in an RFC 822 message.
    return d->value.utf8();
}


/*! If the header field is valid(), this function returns the contents
    of this header field in a representation that is meant for storage
    in the database (unfolded and UTF-8 encoded, with RFC 2047
    encoded-words expanded).

    If the field is not valid(), this function returns an empty
    string.

    Use rfc822() if you want a valid RFC 2822 representation.
*/

UString HeaderField::value() const
{
    return d->value;
}


/*! Sets the parsed representation of this HeaderField to \a s and
    clears the error().
*/

void HeaderField::setValue( const UString &s )
{
    d->value = s;
    d->error.truncate();
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


/*! Every HeaderField subclass must define a parse() function that takes
    a string \a s from a message and sets the field value(). This default
    function handles fields that are not specially handled by subclasses
    using functions like parseText().
*/

void HeaderField::parse( const String &s )
{
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

    case ContentDescription:
    case Subject:
    case Comments:
        parseText( s );
        break;

    case MimeVersion:
        parseMimeVersion( s );
        break;

    case ContentLocation:
        parseContentLocation( s );
        break;

    case ContentBase:
        parseContentBase( s );
        break;

    case InReplyTo:
    case Keywords:
    case Received:
    case ContentMd5:
    case Other:
        parseOther( s );
        break;
    }

    if ( !valid() )
        d->unparsed = s;
}


/*! Parses the *text production from \a s, as modified to include
    encoded-words by RFC 2047. This is used to parse the Subject
    and Comments fields.
*/

void HeaderField::parseText( const String &s )
{
    bool h = false;
    if ( !h ) {
        EmailParser p( s );
        UString t( p.text() );
        if ( p.atEnd() ) {
            setValue( t );
            h = true;
        }
    }

    if ( !h ) {
        EmailParser p( s.simplified() );
        UString t( p.text() );
        if ( p.atEnd() ) {
            setValue( t );
            h = true;
        }
    }

    if ( !h &&
         s.startsWith( "=?" ) &&
         s.endsWith( "?=" ) &&
         !s.mid( 2 ).contains( "=?" ) ) {
        // Cope with the following common error:
        // Subject: =?ISO-8859-1?q?foo bar baz?=
        EmailParser p( StringList::split( ' ', s.simplified() )->join( "_" ) );
        UString t( p.text() );
        if ( p.atEnd() ) {
            setValue( t );
            h = true;
        }
    }

    if ( !h )
        setError( "Error parsing text" );
}


/*! Tries to parses any (otherwise uncovered and presumably
    unstructured) field in \a s, and records an error if it contains
    NULs or 8-bit characters.
*/

void HeaderField::parseOther( const String &s )
{
    AsciiCodec a;
    setValue( a.toUnicode( s ) );
    if ( a.valid() )
        return;

    setError( "Unencoded 8-bit data seen: " + a.error() );
}


/*! Parses the Mime-Version field from \a s and resolutely ignores all
    problems seen.

    Only version 1.0 is legal. Since vast numbers of spammers send
    other version numbers, we replace other version numbers with 1.0
    and a comment. Bayesian analysis tools will probably find the
    comment to be a sure spam sign.
*/

void HeaderField::parseMimeVersion( const String &s )
{
    EmailParser p( s );
    p.comment();
    String v = p.dotAtom();
    p.comment();
    AsciiCodec a;
    UString c = a.toUnicode( p.lastComment().simplified() );
    if ( !a.valid() ||
         c.contains( '(' ) || c.contains( ')' ) || c.contains( '\\' ) )
        c.truncate();
    if ( v != "1.0" || !p.atEnd() )
        c = a.toUnicode( "Note: Original mime-version had syntax problems" );
    UString u;
    u.append( "1.0" );
    if ( !c.isEmpty() ) {
        u.append( " (" );
        u.append( c );
        u.append( ")" );
    }
    setValue( u );
}


/*! Parses the Content-Location header field in \a s and records the
    first problem found.
*/

void HeaderField::parseContentLocation( const String &s )
{
    EmailParser p( s.trimmed().unquoted() );

    p.whitespace();
    uint e = p.pos();
    bool ok = true;
    String r;
    while ( ok ) {
        ok = true;
        char c = p.nextChar();
        p.step();
        if ( c == '%' ) {
            String hex;
            hex.append( p.nextChar() );
            p.step();
            hex.append( p.nextChar() );
            p.step();
            c = hex.number( &ok, 16 );
        }

        // RFC 1738 unreserved
        if ( ( c >= 'a' && c <= 'z' ) || // alpha
             ( c >= 'A' && c <= 'Z' ) ||
             ( c >= '0' && c <= '9' ) || // letter
             ( c == '$' || c ==  '-' || // safe
               c ==  '_' || c == '.' ||
               c == '+' ) ||
             ( c == '!' || c ==  '*' || // extra
               c ==  '\'' || c ==  '(' ||
               c ==  ')' || c ==  ',' ) ) {
            r.append( c );
        }
        // RFC 1738 reserved
        else if ( c == ';' || c == '/' || c == '?' ||
                  c == ':' || c == '@' || c == '&' ||
                  c == '=' ) {
            r.append( c );
        }
        // RFC 1738 escape
        else if ( c == '%' || c >= 127 ) {
            String hex = String::fromNumber( c, 16 );
            r.append( "%" );
            if ( hex.length() < 2 )
                r.append( "0" );
            r.append( hex.lower() );
        }
        // seen in real life, sent by buggy programs
        else if ( c == ' ' ) {
            r.append( "%20" );
        }
        // and another kind of bug, except that in this case, is there
        // a right way? let's not flame programs which do this.
        else if ( c == '\r' || c == '\n' ) {
            p.whitespace();
        }
        else {
            ok = false;
        }
        if ( ok )
            e = p.pos();
    }
    p.whitespace();

    AsciiCodec a;
    setValue( a.toUnicode( r ) );
    if ( !p.atEnd() )
        setError( "Junk at position " + fn( e ) + ": " + s.mid( e ) );
    else if ( !a.valid() )
        setError( "Bad character seen: " + a.error() );
}


/*! Parses the Content-Base header field in \a s and records the first
    problem found. Somewhat overflexibly assumes that if there is a
    colon, the URL is absolute, so it accepts -:/asr as a valid URL.
*/

void HeaderField::parseContentBase( const String & s )
{
    parseContentLocation( s );
    if ( !valid() )
        return;
    if ( !value().contains( ":" ) )
        setError( "URL has no scheme" );
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


/*! Returns the Type corresponding to field name \a n, or 0 if \a n
    isn't known.
*/

uint HeaderField::fieldType( const String & n )
{
    String fn = n.headerCased();
    if ( fn.endsWith( ":" ) )
        fn.truncate( fn.length()-1 );
    uint i = 0;
    while ( fieldNames[i].name && fn != fieldNames[i].name )
        i++;
    if ( fieldNames[i].name )
        return fieldNames[i].type;
    return 0;
}


/*! Returns a version of \a s with long lines wrapped according to the
    rules in RFC [2]822. This function is not static, because it needs
    to look at the field name.

    XXX: Well, except that we ignore the rules right now.
*/

String HeaderField::wrap( const String &s ) const
{
    return s.wrapped( 78, d->name + ": ", " ", false ).mid( d->name.length() + 2 );
}


/*! This static function returns an RFC 2047 encoded-word representing
    \a w.
*/

String HeaderField::encodeWord( const UString &w )
{
    if ( w.isEmpty() )
        return "";

    Codec * c = Codec::byString( w );
    String cw( c->fromUnicode( w ) );

    String t( "=?" );
    t.append( c->name() );
    t.append( "?" );
    String qp = cw.eQP( true );
    String b64 = cw.e64();
    if ( qp.length() <= b64.length() + 3 &&
         t.length() + qp.length() <= 73 ) {
        t.append( "q?" );
        t.append( qp );
        t.append( "?=" );
    }
    else {
        String prefix = t;
        prefix.append( "b?" );
        t = "";
        while ( !b64.isEmpty() ) {
            uint allowed = 73 - prefix.length();
            allowed = 4 * (allowed/4);
            String word = prefix;
            word.append( b64.mid( 0, allowed ) );
            word.append( "?=" );
            b64 = b64.mid( allowed );
            t.append( word );
            if ( !b64.isEmpty() )
                t.append( " " );
        }
    }

    return t;
}


/*! This static function returns the RFC 2047-encoded version of \a s.
*/

String HeaderField::encodeText( const UString &s )
{
    StringList r;
    AsciiCodec a;
    UStringList::Iterator w( UStringList::split( ' ', s ) );
    while ( w ) {
        UStringList l;
        while ( w && !w->isAscii() ) {
            l.append( w );
            ++w;
        }
        if ( !l.isEmpty() )
            r.append( encodeWord( l.join( " " ) ) );
        while ( w && w->isAscii() ) {
            r.append( a.fromUnicode( *w ) );
            ++w;
        }
    }
    return r.join( " " );
}


/*! This static function returns the RFC 2047-encoded version of \a s.
*/

String HeaderField::encodePhrase( const UString &s )
{
    String t;
    UStringList::Iterator it( UStringList::split( ' ', s.simplified() ) );

    while ( it ) {
        UString w( *it );
        ++it;

        if ( !t.isEmpty() )
            t.append( " " );

        if ( w.isAscii() && w.ascii().boring() ) {
            t.append( w.ascii() );
        }
        else {
            while ( it && !( (*it).isAscii() && (*it).ascii().boring() ) ) {
                w.append( " " );
                w.append( *it );
                ++it;
            }
            t.append( encodeWord( w ) );
        }
    }

    return t;
}


/*! Records the position of this header field, \a p. This function
    doesn't move the header field in the lost used by Header, it
    merely records the position so that Header can access it when
    needed.
*/

void HeaderField::setPosition( uint p )
{
    d->position = p;
}


/*! Returns the header field's position, as recorded by setPosition().
    The initial value is UINT_MAX, which is magic. When Header sees
    UINT_MAX, it changes the position() to one higher than the highest
    existing position.
*/

uint HeaderField::position() const
{
    return d->position;
}


/*! Returns the header field's value() completely unparsed, if
    !valid(). If the field is valid(), this function returns an empty
    string.

*/

String HeaderField::unparsedValue() const
{
    if ( valid() )
        d->unparsed.truncate();

    return d->unparsed;
}
