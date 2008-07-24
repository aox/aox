// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "mimefields.h"

#include "field.h"
#include "string.h"
#include "ustring.h"
#include "parser.h"
#include "codec.h"
#include "list.h"
#include "map.h"
#include "utf.h"


class MimeFieldData
    : public Garbage
{
public:
    struct Parameter
        : public Garbage
    {
        String name;
        String value;
        Map<String> parts;
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

void MimeField::parseParameters( EmailParser *p )
{
    bool done = false;
    bool first = true;
    while ( valid() && !done ) {
        done = true;
        uint i = p->pos();
        while ( p->nextChar() == ';' ||
                p->nextChar() == ' ' || p->nextChar() == '\t' ||
                p->nextChar() == '\r' || p->nextChar() == '\n' ||
                p->nextChar() == '"' )
            p->step();
        if ( i < p->pos() )
            done = false;
        if ( first )
            done = false;
        if ( p->atEnd() )
            done = true;
        first = false;
        if ( !done ) {
            String n = p->mimeToken().lower();
            p->comment();
            bool havePart = false;
            uint partNumber = 0;

            if ( n.isEmpty() )
                return;

            if ( n.contains( "*" ) ) {
                uint star = n.find( "*" );
                bool numberOk = false;
                partNumber = n.mid( star+1 ).number( &numberOk );
                if ( numberOk ) {
                    havePart = true;
                    n = n.mid( 0, star );
                }
            }
            if ( type() == ContentType && p->atEnd() && Codec::byName( n ) ) {
                // sometimes we see just iso-8859-1 instead of
                // charset=iso-8859-1.
                List< MimeFieldData::Parameter >::Iterator it( d->parameters );
                while ( it && it->name != "charset" )
                    ++it;
                if ( !it ) {
                    MimeFieldData::Parameter * pm 
                        = new MimeFieldData::Parameter;
                    pm->name = "charset";
                    pm->value = n;
                    d->parameters.append( pm );
                    it = d->parameters.find( pm );
                    return;
                }
            }
            if ( p->nextChar() == ':' && HeaderField::fieldType( n ) ) {
                // some spammers send e.g. 'c-t: stuff subject:
                // stuff'.  we ignore the second field entirely. who
                // cares about spammers.
                n.truncate();
                p->step( p->input().length() );
            }
            else if ( p->nextChar() != '=' ) {
                return;
            }

            p->step();
            p->whitespace();
            String v;
            if ( p->nextChar() == '"' ) {
                v = p->mimeValue();
            }
            else {
                uint start = p->pos();
                v = p->mimeValue();
                bool ok = true;
                while ( ok && !p->atEnd() &&
                        p->nextChar() != ';' &&
                        p->nextChar() != '"' ) {
                    if ( p->dotAtom().isEmpty() && p->mimeValue().isEmpty() )
                        ok = false;
                }
                if ( ok )
                    v = p->input().mid( start, p->pos()-start );
            }
            p->comment();

            if ( !n.isEmpty() ) {
                List< MimeFieldData::Parameter >::Iterator it( d->parameters );
                while ( it && n != it->name )
                    ++it;
                if ( !it ) {
                    MimeFieldData::Parameter * pm
                        = new MimeFieldData::Parameter;
                    pm->name = n;
                    d->parameters.append( pm );
                    it = d->parameters.find( pm );
                }
                if ( havePart )
                    it->parts.insert( partNumber, new String( v ) );
                else
                    it->value = v;
            }
        }
    }

    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it ) {
        if ( it->value.isEmpty() && it->parts.find( 0 ) ) {
            // I get to be naughty too sometimes
            uint n = 0;
            String * v;
            while ( (v=it->parts.find( n++ )) )
                it->value.append( *v );
        }
        ++it;
    }
}


String MimeField::rfc822() const
{
    String s = baseValue();
    uint lineLength = name().length() + 2 + s.length();

    StringList words;
    List< MimeFieldData::Parameter >::Iterator it( d->parameters );
    while ( it ) {
        String s = it->value;
        if ( !s.boring( String::MIME ) )
            s = s.quoted();
        words.append( it->name + "=" + s );
        ++it;
    }

    while ( !words.isEmpty() ) {
        StringList::Iterator i( words );
        while ( i && lineLength + 2 + i->length() > 78 )
            ++i;
        if ( i ) {
            s.append( "; " );
            lineLength += 2;
        }
        else {
            i = words;
            s.append( ";\r\n " );
            lineLength = 1;
        }
        s.append( *i ); // XXX need more elaboration for 2231
        lineLength += i->length();
        words.take( i );
    }
    return s;
}


/*! Like HeaderField::value(), returns the contents of this MIME field in
    a representation suitable for storage.
*/

UString MimeField::value() const
{
    Utf8Codec c;
    return c.toUnicode( rfc822() );
    // the best that can be said about this is that it corresponds to
    // HeaderField::assemble.
}


/*! \fn virtual String MimeField::baseValue() const

    This pure virtual function is used by rfc822() and value() to
    fetch the value of this header field without any parameters().
    rfc822() and value() then append the parameters().
*/



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
    EmailParser p( s );
    p.whitespace();

    if ( p.atEnd() ) {
        t = "text";
        st = "plain";
    }
    else {
        uint x = p.mark();
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
                setError( "Invalid Content-Type: " + s.quoted() );
            }
        }
        else {
            bool mustGuess = false;
            if ( p.nextChar() == '/' ) {
                // eek. this makes mime look like the special case.
                p.step();
                st = p.mimeToken().lower();
            }
            else if ( p.nextChar() == '=' ) {
                // oh no. someone skipped the content-type and
                // supplied only some parameters. we'll assume it's
                // text/plain and parse the parameters.
                t = "text";
                st = "plain";
                p.restore( x );
            }
            else {
                addParameter( "original-type", t + "/" + st );
                t = "application";
                st = "octet-stream";
                mustGuess = true;
            }
            parseParameters( &p );
            if ( mustGuess ) {
                String fn = parameter( "name" );
                if ( fn.isEmpty() )
                    fn = parameter( "filename" );
                while ( fn.endsWith( "." ) )
                    fn.truncate( fn.length() - 1 );
                while ( fn.contains( '.' ) )
                    fn = fn.section( ".", 2 );
                fn = fn.lower();
                if ( fn == "jpg" || fn == "jpeg" ) {
                    t = "image";
                    st = "jpeg";
                }
                else if ( fn == "htm" || fn == "html" ) {
                    t = "text";
                    st = "html";
                }
                else {
                    t = "application";
                    st = "octet-stream";
                }
            }
        }
    }

    if ( t.isEmpty() || st.isEmpty() )
        setError( "Both type and subtype must be nonempty: " + s.quoted() );

    if ( valid() && !p.atEnd() &&
         t == "multipart" && parameter( "boundary" ).isEmpty() &&
         s.lower().containsWord( "boundary" ) ) {
        EmailParser csp( s.mid( s.lower().find( "boundary" ) ) );
        csp.require( "boundary" );
        csp.whitespace();
        if ( csp.present( "=" ) )
            csp.whitespace();
        uint m = csp.mark();
        String b = csp.string();
        if ( b.isEmpty() || !csp.ok() ) {
            csp.restore( m );
            b = csp.input().mid( csp.pos() ).section( ";", 1 ).simplified();
            if ( !b.isQuoted() )
                b.replace( "\\", "" );
            if ( b.isQuoted() )
                b = b.unquoted();
            else if ( b.isQuoted( '\'' ) )
                b = b.unquoted( '\'' );
       }
        if ( !b.isEmpty() )
            addParameter( "boundary", b );
    }

    if ( valid() && t == "multipart" && parameter( "boundary" ).isEmpty() )
        setError( "Multipart entities must have a boundary parameter." );

    if ( !parameter( "charset" ).isEmpty() ) {
        Codec * c = Codec::byName( parameter( "charset" ) );
        if ( c ) {
            String cs = c->name().lower();
            if ( t == "text" && cs == "us-ascii" )
                removeParameter( "charset" );
            else if ( t == "text" && st == "html" && cs == "iso-8859-1" )
                removeParameter( "charset" );
            else if ( cs != parameter( "charset" ).lower() )
                addParameter( "charset", cs );
        }
    }

    if ( valid() && !p.atEnd() &&
         t == "text" && parameter( "charset" ).isEmpty() &&
         s.mid( p.pos() ).lower().containsWord( "charset" ) ) {
        EmailParser csp( s.mid( s.lower().find( "charset" ) ) );
        csp.require( "charset" );
        csp.whitespace();
        if ( csp.present( "=" ) )
            csp.whitespace();
        Codec * c = Codec::byName( csp.dotAtom() );
        if ( c )
            addParameter( "charset", c->name().lower() );
    }
}


/*! Returns the media type as a lower-case string. */

String ContentType::type() const
{
    return t;
}


/*! Returns the media subtype as a lower-case string. */

String ContentType::subtype() const
{
    return st;
}


String ContentType::baseValue() const
{
    return t + "/" + st;
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
    EmailParser p( s );

    String t = p.mimeValue().lower();
    p.comment();
    // XXX shouldn't we do p.end() here and record parse errors?

    if ( t == "7bit" || t == "8bit" || t == "8bits" || t == "binary" ||
         t == "unknown" )
        setEncoding( String::Binary );
    else if ( t == "quoted-printable" )
        setEncoding( String::QP );
    else if ( t == "base64" )
        setEncoding( String::Base64 );
    else if ( t == "x-uuencode" || t == "uuencode" )
        setEncoding( String::Uuencode );
    else if ( t.contains( "bit" ) && t[0] >= '0' && t[0] <= '9' )
        setEncoding( String::Binary );
    else
        setError( "Invalid c-t-e value: " + t.quoted() );
}


/*! Sets the encoding of this ContentTransferEncoding object to \a en.
    This is a special hack for use by Bodypart::parseBodypart() in an
    attempt to preserve field order.
*/

void ContentTransferEncoding::setEncoding( String::Encoding en )
{
    e = en;
}


/*! Returns the encoding, or Binary in case of error. */

String::Encoding ContentTransferEncoding::encoding() const
{
    return e;
}


String ContentTransferEncoding::baseValue() const
{
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
    return s;
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
    EmailParser p( s );

    uint m = p.mark();
    String t = p.mimeToken().lower();
    p.whitespace();
    if ( p.nextChar() == '=' && t != "inline" && t != "attachment" )
        p.restore( m ); // handle c-d: filename=foo

    if ( t.isEmpty() ) {
        setError( "Invalid disposition" );
        return;
    }
    parseParameters( &p );

    // We are required to treat unknown types as "attachment". If they
    // are syntactically invalid, we replace them with "attachment".
    if ( t.isEmpty() )
        d = "attachment";
    else
        d = t;
}


/*! Returns the disposition. */

ContentDisposition::Disposition ContentDisposition::disposition() const
{
    if ( d == "inline" )
        return Inline;
    else
        return Attachment;
}


String ContentDisposition::baseValue() const
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
    EmailParser p( s );

    do {
        // We're not going to bother trying to validate language tags.
        p.comment();
        String t = p.mimeToken();
        if ( t != "" )
            l.append( t );
        p.comment();
    } while ( p.present( "," ) );

    if ( !p.atEnd() || l.count() == 0 )
        setError( "Unparseable value: " + s.quoted() );
}


/*! Returns the list of language tags. */

const StringList *ContentLanguage::languages() const
{
    return &l;
}


String ContentLanguage::baseValue() const
{
    return l.join( ", " );
}
