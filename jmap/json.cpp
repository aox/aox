// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "json.h"

#include "dict.h"
#include "utf.h"
#include "estringlist.h"


class JsonData
    : public Garbage
{
public:
    JsonData()
        : type( Json::Null ), boolean( false ), number( 0 ),
          array( 0 ), object( 0 ), keys( 0 )
    {}

    Json::Type type;
    bool boolean;
    int64 number;
    UString string;
    List<Json> * array;
    Dict<Json> * object;
    EStringList * keys;
};


/*! \class Json json.h

    The Json class is a JSON value: a parser for untrusted input and a
    writer for what we send back.

    The parser is deliberately strict. Input that is not well-formed
    JSON, not valid UTF-8, nested more than 32 deep or longer than the
    caller allows is rejected with an error message rather than
    interpreted generously, because every byte of it comes from the
    network and generosity is how a parser becomes an attack surface.

    Numbers are integers. JSON permits a fraction and an exponent, and
    JMAP has no use for either, so a fraction is an error instead of a
    rounding decision made on an attacker's behalf.

    Duplicate object members are an error too. JSON does not say which
    one wins, which means two implementations can disagree about what a
    document says - and a request whose meaning depends on that is one
    we would rather not answer at all.
*/


/*! Constructs a JSON value of type \a t, empty or zero. */

Json::Json( Type t )
    : d( new JsonData )
{
    d->type = t;
    if ( t == Array )
        d->array = new List<Json>;
    if ( t == Object ) {
        d->object = new Dict<Json>;
        d->keys = new EStringList;
    }
}


/*! Returns the type of this value. */

Json::Type Json::type() const
{
    return d->type;
}


/*! Returns true if this value is of type \a t. A convenience for
    checking what arrived before using it.
*/

bool Json::valid( Type t ) const
{
    return d->type == t;
}


/*! Returns the value of a Boolean, or false. */

bool Json::boolean() const
{
    return d->boolean;
}


/*! Returns the value of a Number, or 0. */

int64 Json::number() const
{
    return d->number;
}


/*! Returns the value of a String, or an empty string. */

UString Json::string() const
{
    return d->string;
}


/*! Returns the value of a String as ASCII, with any non-ASCII
    character replaced by a question mark. Ids and keywords are ASCII,
    and this says so at the point of use.
*/

EString Json::ascii() const
{
    EString r;
    uint i = 0;
    while ( i < d->string.length() ) {
        if ( d->string[i] < 128 )
            r.append( (char)d->string[i] );
        else
            r.append( '?' );
        i++;
    }
    return r;
}


/*! Returns the members of an Array, or a null pointer. */

List<Json> * Json::array() const
{
    return d->array;
}


/*! Returns the member of an Object called \a name, or a null pointer
    if this is not an object or has no such member.
*/

Json * Json::member( const EString & name ) const
{
    if ( !d->object )
        return 0;
    return d->object->find( name );
}


/*! Returns the names of an Object's members, in the order they were
    added or parsed, or a null pointer.
*/

EStringList * Json::members() const
{
    return d->keys;
}


/*! Appends \a v to this Array. */

void Json::append( Json * v )
{
    if ( d->array && v )
        d->array->append( v );
}


/*! Adds \a v to this Object as \a name. */

void Json::insert( const EString & name, Json * v )
{
    if ( !d->object || !v )
        return;
    if ( !d->object->find( name ) )
        d->keys->append( name );
    d->object->insert( name, v );
}


/*! Makes this a Boolean with value \a b. */

void Json::setBoolean( bool b )
{
    d->type = Boolean;
    d->boolean = b;
}


/*! Makes this a Number with value \a n. */

void Json::setNumber( int64 n )
{
    d->type = Number;
    d->number = n;
}


/*! Makes this a String with value \a s. */

void Json::setString( const UString & s )
{
    d->type = String;
    d->string = s;
}


/*! Makes this a String with value \a s, which must be ASCII. */

void Json::setString( const EString & s )
{
    AsciiCodec a;
    setString( a.toUnicode( s ) );
}


/*! Returns a new, empty Object. */

Json * Json::object()
{
    return new Json( Object );
}


/*! Returns a new, empty Array. */

Json * Json::list()
{
    return new Json( Array );
}


/*! Returns a new Number with value \a n. */

Json * Json::number( int64 n )
{
    Json * r = new Json( Number );
    r->setNumber( n );
    return r;
}


/*! Returns a new Boolean with value \a b. */

Json * Json::boolean( bool b )
{
    Json * r = new Json( Boolean );
    r->setBoolean( b );
    return r;
}


/*! Returns a new String with value \a s. */

Json * Json::string( const UString & s )
{
    Json * r = new Json( String );
    r->setString( s );
    return r;
}


/*! Returns a new String with value \a s, which must be ASCII. */

Json * Json::string( const EString & s )
{
    Json * r = new Json( String );
    r->setString( s );
    return r;
}


static void writeString( EString & r, const UString & s )
{
    r.append( '"' );
    uint i = 0;
    while ( i < s.length() ) {
        uint c = s[i];
        if ( c == '"' )
            r.append( "\\\"" );
        else if ( c == '\\' )
            r.append( "\\\\" );
        else if ( c == '\n' )
            r.append( "\\n" );
        else if ( c == '\r' )
            r.append( "\\r" );
        else if ( c == '\t' )
            r.append( "\\t" );
        else if ( c == 8 )
            r.append( "\\b" );
        else if ( c == 12 )
            r.append( "\\f" );
        else if ( c < 32 || c == 127 ) {
            EString h;
            h.appendNumber( c, 16 );
            while ( h.length() < 4 )
                h = "0" + h;
            r.append( "\\u" + h );
        }
        else if ( c < 128 ) {
            r.append( (char)c );
        }
        else {
            // The rest goes out as UTF-8: JSON is UTF-8 by RFC8259 8.1
            // and escaping would only make the output bigger and the
            // addresses in it unreadable.
            UString one;
            one.append( c );
            Utf8Codec u;
            r.append( u.fromUnicode( one ) );
        }
        i++;
    }
    r.append( '"' );
}


/*! Returns this value as JSON text, without gratuitous whitespace. */

EString Json::write() const
{
    EString r;
    switch ( d->type ) {
    case Null:
        r.append( "null" );
        break;
    case Boolean:
        r.append( d->boolean ? "true" : "false" );
        break;
    case Number:
        r.appendNumber( d->number );
        break;
    case String:
        writeString( r, d->string );
        break;
    case Array:
        {
            r.append( '[' );
            List<Json>::Iterator i( d->array );
            while ( i ) {
                r.append( i->write() );
                ++i;
                if ( i )
                    r.append( ',' );
            }
            r.append( ']' );
        }
        break;
    case Object:
        {
            r.append( '{' );
            EStringList::Iterator i( d->keys );
            while ( i ) {
                AsciiCodec a;
                writeString( r, a.toUnicode( *i ) );
                r.append( ':' );
                r.append( d->object->find( *i )->write() );
                ++i;
                if ( i )
                    r.append( ',' );
            }
            r.append( '}' );
        }
        break;
    }
    return r;
}


class JsonParser
    : public Garbage
{
public:
    JsonParser( const EString & t )
        : text( t ), i( 0 ), depth( 0 ) {}

    EString text;
    uint i;
    uint depth;
    EString error;

    void whitespace()
    {
        while ( i < text.length() &&
                ( text[i] == ' ' || text[i] == '\t' ||
                  text[i] == '\n' || text[i] == '\r' ) )
            i++;
    }

    void fail( const EString & e )
    {
        if ( error.isEmpty() )
            error = e + " at byte " + fn( i );
    }

    bool present( const EString & s )
    {
        if ( text.mid( i, s.length() ) != s )
            return false;
        i += s.length();
        return true;
    }

    UString string()
    {
        UString r;
        if ( text[i] != '"' ) {
            fail( "Expected a string" );
            return r;
        }
        i++;
        EString utf8;
        while ( i < text.length() && text[i] != '"' ) {
            if ( text[i] == '\\' ) {
                i++;
                char c = text[i];
                i++;
                if ( c == '"' || c == '\\' || c == '/' )
                    utf8.append( c );
                else if ( c == 'n' )
                    utf8.append( '\n' );
                else if ( c == 'r' )
                    utf8.append( '\r' );
                else if ( c == 't' )
                    utf8.append( '\t' );
                else if ( c == 'b' )
                    utf8.append( (char)8 );
                else if ( c == 'f' )
                    utf8.append( (char)12 );
                else if ( c == 'u' ) {
                    bool ok = false;
                    uint n = text.mid( i, 4 ).number( &ok, 16 );
                    if ( !ok || text.mid( i, 4 ).length() < 4 ) {
                        fail( "Bad \\u escape" );
                        return r;
                    }
                    i += 4;
                    if ( n >= 0xd800 && n < 0xdc00 ) {
                        // a leading surrogate needs its partner
                        if ( !present( "\\u" ) ) {
                            fail( "Lone leading surrogate" );
                            return r;
                        }
                        uint l = text.mid( i, 4 ).number( &ok, 16 );
                        if ( !ok || l < 0xdc00 || l >= 0xe000 ) {
                            fail( "Bad trailing surrogate" );
                            return r;
                        }
                        i += 4;
                        n = 0x10000 + ( ( n - 0xd800 ) << 10 ) + ( l - 0xdc00 );
                    }
                    else if ( n >= 0xdc00 && n < 0xe000 ) {
                        fail( "Lone trailing surrogate" );
                        return r;
                    }
                    UString one;
                    one.append( n );
                    Utf8Codec u;
                    utf8.append( u.fromUnicode( one ) );
                }
                else {
                    fail( "Unknown escape" );
                    return r;
                }
            }
            else if ( (unsigned char)text[i] < 32 ) {
                fail( "Unescaped control character in string" );
                return r;
            }
            else {
                utf8.append( text[i] );
                i++;
            }
        }
        if ( i >= text.length() ) {
            fail( "Unterminated string" );
            return r;
        }
        i++;
        Utf8Codec u;
        r = u.toUnicode( utf8 );
        if ( !u.valid() )
            fail( "Invalid UTF-8 in string: " + u.error() );
        return r;
    }

    Json * value()
    {
        if ( !error.isEmpty() )
            return 0;
        if ( depth > 32 ) {
            fail( "Nested too deeply" );
            return 0;
        }
        whitespace();
        if ( i >= text.length() ) {
            fail( "Expected a value" );
            return 0;
        }
        char c = text[i];
        if ( c == '{' )
            return object();
        if ( c == '[' )
            return array();
        if ( c == '"' ) {
            UString s = string();
            if ( !error.isEmpty() )
                return 0;
            return Json::string( s );
        }
        if ( present( "true" ) )
            return Json::boolean( true );
        if ( present( "false" ) )
            return Json::boolean( false );
        if ( present( "null" ) )
            return new Json( Json::Null );
        return integer();
    }

    Json * integer()
    {
        uint start = i;
        if ( text[i] == '-' )
            i++;
        uint digits = 0;
        while ( i < text.length() && text[i] >= '0' && text[i] <= '9' ) {
            i++;
            digits++;
        }
        if ( !digits ) {
            fail( "Expected a value" );
            return 0;
        }
        if ( i < text.length() &&
             ( text[i] == '.' || text[i] == 'e' || text[i] == 'E' ) ) {
            fail( "Numbers must be integers here" );
            return 0;
        }
        bool ok = false;
        EString n = text.mid( start, i - start );
        int64 v = 0;
        if ( n.startsWith( "-" ) ) {
            v = 0 - (int64)n.mid( 1 ).number( &ok );
        }
        else {
            v = (int64)n.number( &ok );
        }
        if ( !ok ) {
            fail( "Number out of range: " + n );
            return 0;
        }
        return Json::number( v );
    }

    Json * array()
    {
        Json * r = Json::list();
        i++; // past [
        depth++;
        whitespace();
        if ( text[i] == ']' ) {
            i++;
            depth--;
            return r;
        }
        bool more = true;
        while ( more && error.isEmpty() ) {
            Json * v = value();
            if ( !v )
                return 0;
            r->append( v );
            whitespace();
            more = false;
            if ( i < text.length() && text[i] == ',' ) {
                i++;
                more = true;
            }
        }
        whitespace();
        if ( i >= text.length() || text[i] != ']' ) {
            fail( "Expected , or ]" );
            return 0;
        }
        i++;
        depth--;
        return r;
    }

    Json * object()
    {
        Json * r = Json::object();
        i++; // past {
        depth++;
        whitespace();
        if ( text[i] == '}' ) {
            i++;
            depth--;
            return r;
        }
        bool more = true;
        while ( more && error.isEmpty() ) {
            whitespace();
            UString name = string();
            if ( !error.isEmpty() )
                return 0;
            Utf8Codec u;
            EString n = u.fromUnicode( name );
            if ( r->member( n ) ) {
                fail( "Duplicate member: " + n.quoted() );
                return 0;
            }
            whitespace();
            if ( i >= text.length() || text[i] != ':' ) {
                fail( "Expected :" );
                return 0;
            }
            i++;
            Json * v = value();
            if ( !v )
                return 0;
            r->insert( n, v );
            whitespace();
            more = false;
            if ( i < text.length() && text[i] == ',' ) {
                i++;
                more = true;
            }
        }
        whitespace();
        if ( i >= text.length() || text[i] != '}' ) {
            fail( "Expected , or }" );
            return 0;
        }
        i++;
        depth--;
        return r;
    }
};


/*! Parses \a text as JSON and returns the value, or a null pointer if
    \a text is not acceptable, in which case \a error says why.
*/

Json * Json::parse( const EString & text, EString & error )
{
    JsonParser p( text );
    Json * r = p.value();
    if ( r ) {
        p.whitespace();
        if ( p.i < text.length() )
            p.fail( "Trailing garbage" );
    }
    if ( !p.error.isEmpty() ) {
        error = p.error;
        return 0;
    }
    error.truncate( 0 );
    return r;
}
