// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievescript.h"

#include "list.h"


class SieveScriptData
    : public Garbage
{
public:
    SieveScriptData(): Garbage(), pos( 0 ) {}

    ::String source;
    uint pos;

    class Production
        : public Garbage
    {
    public:
        Production( SieveScriptData * mothership, ::String name );
        Production( Production * inside, ::String name );
        virtual ~Production() {}

        uint errorLine() const;

        Production * parent() { return mommy; }

        const ::String name() { return n; }
        const ::String & source() const { return d->source; }
        uint & pos() const { return d->pos; }
        char nextChar() const { return source()[pos()]; }
        void skip( uint l ) { pos() += l; }
        void skip( const ::String & l ) { pos() += l.length(); }

        virtual void parse() = 0;

        bool lookingAt( const ::String & l ) const {
            const ::String & s = source();
            uint i = 0;
            while ( i < l.length() ) {
                char cl = l[i];
                char cs = s[pos()+i];
                if ( cs == cl ) {
                    // ok - exact match
                } else if ( cl == cs + 32 && cs >= 'A' && cs <= 'Z' ) {
                    // ok - have upper-case, looking for lower
                } else if ( cl == cs - 32 && cs >= 'a' && cs <= 'z' ) {
                    // ok - have lower-case, looking for upper
                }
                else {
                    return false; // not a match
                }
                i++;
            }
            return true;
        }

        bool present( const ::String & l ) {
            if ( lookingAt( l ) ) {
                skip( l );
                return true;
            }
            return false;
        }

        void error( const ::String & );

        void require( const ::String & l ) {
            if ( !present( l ) )
                error( l + " expected" );
        }

        String letters() {
            uint s = pos();
            char c = source()[pos()];
            while ( ( c >= 'a' && c <= 'z' ) ||
                    ( c >= 'A' && c <= 'Z' ) )
                c = source()[++pos()]; // ick! ick! ikk!
            return source().mid( s, pos() - s ).lower();
        }
        
    public:
        uint start;
        Production * mommy;
        SieveScriptData * d;
        ::String n;
        ::String e;
        uint bang;
    };

    template<class T>
    class ProductionList
        : public Production
    {
    public:
        ProductionList( Production * p )
            : Production( p, (new T(p))->name() + "-list" ),
              c( new List<T> ) {
            while ( true ) {
                uint before = d->pos;
                T * t = new T( this );
                if ( d->pos == before )
                    return;
                c->append( t );
            }
        }
        List<T> * children() const { return c; }
        void parse() {
            // if we have min/max requirements, this is where we check
        }
    private:
        List<T> * c;
    };

    // bracket-comment = "/*" *not-star 1*STAR
    //                    *(not-star-slash *not-star 1*STAR) "/"
    class BracketComment
        : public Production
    {
    public:
        BracketComment( Production * );
        void parse();
    private:
    };

    // hash-comment = "#" *octet-not-crlf CRLF
    class HashComment
        : public Production
    {
    public:
        HashComment( Production * );
        void parse();
    private:
    };

    // identifier = (ALPHA / "_") *(ALPHA / DIGIT / "_")
    class Identifier
        : public Production
    {
    public:
        Identifier( Production * );
        void parse();
    private:
        ::String identifier;
    };

    // number = 1*DIGIT [ QUANTIFIER ]
    class Number
        : public Production
    {
    public:
        Number( Production * );
        void parse();
    private:
        uint number;
    };

    // tag = ":" identifier
    class Tag
        : public Production
    {
    public:
        Tag( Production * );
        void parse();
    private:
        Identifier * id;
    };

    // white-space = 1*(SP / CRLF / HTAB) / comment
    class WhiteSpace
        : public Production
    {
    public:
        WhiteSpace( Production * );
        void parse();
    private:
    };

    // ADDRESS-PART = ":localpart" / ":domain" / ":all"
    class AddressPart
        : public Production
    {
    public:
        AddressPart( Production * );
        void parse();
    private:
        const char * type;
    };

    class StringList;
    class TestList;

    // argument = string-list / number / tag
    class Argument
        : public Production
    {
    public:
        Argument( Production * );
        void parse();
    private:
        class SieveScriptData::Tag * tag;
        class SieveScriptData::Number * number;
        class SieveScriptData::StringList * stringList;
    };

    // arguments = *argument [test / test-list]
    class Arguments
        : public Production
    {
    public:
        Arguments( Production * );
        void parse();
    private:
        SieveScriptData::ProductionList<Argument> * arguments;
        class SieveScriptData::TestList * testList;
    };

    // command = identifier arguments ( ";" / block )
    class Command
        : public Production
    {
    public:
        Command( Production * );
        void parse();
    private:
        Identifier * id;
        Arguments * args;
        ProductionList<Command> * block;
    };

    // string = quoted-string / multi-line
    class String
        : public Production
    {
    public:
        String( Production * );
        void parse();
    private:
        ::String string;
    };

    // COMPARATOR = ":comparator" string
    class Comparator
        : public Production
    {
    public:
        Comparator( Production * );
        void parse();
    private:
        String * comparator;
    };

    // MATCH-TYPE = ":is" / ":contains" / ":matches"
    class MatchType
        : public Production
    {
    public:
        MatchType( Production * );
        void parse();
    private:
        ::String matchType;
    };

    // string-list  = "[" string *("," string) "]" / string
    class StringList
        : public Production
    {
    public:
        StringList( Production * );
        void parse();
    private:
    };

    // test = identifier arguments
    class Test
        : public Production
    {
    public:
        Test( Production * );
        void parse();
    private:
        Identifier * id;
        Arguments * args;
    };

    // test-list - see below
    class TestList
        : public Production
    {
    public:
        TestList( Production * );
        void parse();
    private:
        ::List<Test> * tests;
    };

/*
    class X
        : public Production
    {
    public:
        X( Production * );
        void parse();
    private:
    };
*/
};


SieveScriptData::Production::Production( SieveScriptData * mothership,
                                         ::String name )
    : Garbage(), start( 0 ), mommy( 0 ), d( mothership ), n( name ),
      bang( 0 )
{
}


SieveScriptData::Production::Production( Production * mother,
                                         ::String name )
    : Garbage(),
      start( mother->start ), mommy( mother ), d( mother->d ), n( name ),
      bang( 0 )
{
}


uint SieveScriptData::Production::errorLine() const
{
    uint i = 0;
    uint l = 1;
    while ( i < start ) {
        if ( d->source[i] == '\n' )
            l++;
        i++;
    }
    return l;
}

void SieveScriptData::Production::error( const ::String & message )
{
    if ( !e.isEmpty() )
        return;

    bang = pos();
    e = message;
}


// ADDRESS-PART = ":localpart" / ":domain" / ":all"
SieveScriptData::AddressPart::AddressPart( Production * p )
    : SieveScriptData::Production( p, "addresspart" )
{
    if ( lookingAt( ":localpart" ) )
        type = ":localpart";
    else if ( lookingAt( ":domain" ) )
        type = ":domain";
    else if ( lookingAt( ":all" ) )
        type = ":all";

    if ( type )
        skip( type );
    else
        error( "No valid address-part seen" );
}

void SieveScriptData::AddressPart::parse()
{
}

// argument = string-list / number / tag
SieveScriptData::Argument::Argument( Production * p )
    : SieveScriptData::Production( p, "argument" )
{
    switch ( nextChar() ) {
    case ':':
        tag = new Tag( this );
        break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        number = new Number( this );
        break;
    case '(':
    case '"':
    case 't':
    case 'T':
        stringList = new StringList( this );
        break;
    default:
        error( "No valid argument seen" );
        break;
    }
}

void SieveScriptData::Argument::parse()
{
}


// arguments = *argument [test / test-list]
SieveScriptData::Arguments::Arguments( Production * p )
    : SieveScriptData::Production( p, ":arguments" )
{
    arguments = new SieveScriptData::ProductionList<Argument>( this );
    // see TestList below
    testList = new TestList( this );
}

void SieveScriptData::Arguments::parse()
{
}


// command = identifier arguments ( ";" / block )
SieveScriptData::Command::Command( Production * p )
    : SieveScriptData::Production( p, "Command" ),
      id( 0 ), args( 0 ), block( 0 )
{
    id = new Identifier( this );
    args = new Arguments( this );
    if ( present( ";" ) )
        return;

    // implement block directly here instead of using a separate type,
    // since g++ 4.x has issues with forward declarations

    // block = "{" commands "}"
    require( "{" );
    block = new ProductionList<Command>( this );
    require( "}" );
}

void SieveScriptData::Command::parse()
{
}


// COMPARATOR = ":comparator" string
SieveScriptData::Comparator::Comparator( Production * p )
    : SieveScriptData::Production( p, "comparator" ),
      comparator( 0 )
{
    require( ":comparator" );
    comparator = new String( this );
}

void SieveScriptData::Comparator::parse()
{
}


// MATCH-TYPE = ":is" / ":contains" / ":matches"
SieveScriptData::MatchType::MatchType( Production * p )
    : SieveScriptData::Production( p, "matchtype" )
{
    if ( !present( ":" ) )
        error( "No valid match-type seen" );
    ::String n = letters();
    if ( n == "is" || n == "contains" || n == "matches" )
        matchType = n;
    else
        error( n + ": Invalid match-type" );
}

void SieveScriptData::MatchType::parse()
{
}

// string = quoted-string / multi-line
SieveScriptData::String::String( Production * p )
    : SieveScriptData::Production( p, "string" )
{
    if ( present( "\"" ) ) {
        // quoted-string = DQUOTE quoted-text DQUOTE
        // quoted-text = *(quoted-safe / quoted-special / quoted-other)
        // quoted-safe = CRLF / octet-not-qspecial
        // quoted-special     = "\" ( DQUOTE / "\" )
        // quoted-other = "\" octet-not-qspecial
        // octet-not-qspecial = %x01-09 / %x0B-0C / %x0E-21 / %x23-5B / %x5D-FF
        switch ( nextChar() ) {
        case '"':
            skip( 1 );
            return;
            break;
        case 13:
            skip( 1 );
            if ( nextChar() != 10 )
                error( "CR without following LF" );
            skip( 1 );
            string.append( "\r\n" );
            break;
        case 10:
            error( "LF without preceding CR" );
            break;
        case '\\':
            skip( 1 );
            if ( nextChar() == 0 || nextChar() == 10 || nextChar() == 13 )
                error( "Can't quote NUL, CR or LF" );
            string.append( nextChar() );
            skip( 1 );
            break;
        case 0: // just plain illegal
            error( "0 byte seen" );
            break;
        default: // other-not-qspecial
            string.append( nextChar() );
            skip( 1 );
            break;
        }
    }
    // it has to be a multiline. this function is no fun at all.

    // multi-line = "text:" *(SP / HTAB) (hash-comment / CRLF)
    //              *(multiline-literal / multiline-dotstuff)
    //              "." CRLF

    // multiline-literal = [octet-not-period *octet-not-crlf] CRLF

    // multiline-dotstuff = "." 1*octet-not-crlf CRLF
    //                      ; A line containing only "." ends the
    //                      ; multi-line.  Remove a leading '.' if
    //                      ; followed by another '.'.

    require( "text:" );
    while( nextChar() == ' ' || nextChar() == '\t' )
        skip( 1 );
    if ( nextChar() == '#' )
        (void)new HashComment( this );
    else
        require( "\r\n" );
    bool crlf = true;
    while ( e.isEmpty() ) {
        if ( pos() >= source().length() )
            error( "String ran off end of script" );
        char c = nextChar();
        if ( crlf && c == '.' ) {
            if ( lookingAt( ".\r\n" ) )
                return;
            if ( lookingAt( ".." ) ) {
                skip( 1 );
                c = nextChar();
            }
        }
        string.append( c );
        skip( 1 );
        if ( c == 10 ) {
            error( "LF without CR" );
        }
        else if ( c == 13 ) {
            c = nextChar();
            if ( c != 10 )
                error( "CR without LF" );
            string.append( c );
            skip( 1 );
            crlf = true;
        }
        else {
            crlf = false;
        }
    }
}

void SieveScriptData::String::parse()
{
}

// string-list  = "[" string *("," string) "]" / string
SieveScriptData::StringList::StringList( Production * p )
    : SieveScriptData::Production( p, "::stringlist" )
{
}

void SieveScriptData::StringList::parse()
{
}

// test = identifier arguments
SieveScriptData::Test::Test( Production * p )
    : SieveScriptData::Production( p, "test" ),
      id( 0 ), args( 0 )
{
    id = new Identifier( this );
    args = new Arguments( this );
}

void SieveScriptData::Test::parse()
{
}


// test-list = "(" test *("," test) ")"
// we extend this as follows to make life simpler for users of test-list:
//           = test / ( "(" test *("," test) ")" )
SieveScriptData::TestList::TestList( Production * p )
    : SieveScriptData::Production( p, "test" ), tests( new ::List<Test> )
{
    if ( present( "(" ) ) {
        tests->append( new Test( this ) );
        while( present( "," ) )
            tests->append( new Test( this ) );
        require( ")" );
    }
    else {
        tests->append( new Test( this ) );
    }
}

void SieveScriptData::TestList::parse()
{
}


// bracket-comment = "/*" *not-star 1*STAR
//                    *(not-star-slash *not-star 1*STAR) "/"
SieveScriptData::BracketComment::BracketComment( Production * p )
    : SieveScriptData::Production( p, "bracketcomment" )
{
    require( "/" "*" );
    int e = source().find( "*" "/" );
    if ( e < 0 )
        error( "Comment not terminated" );
    pos() = e + 2;
}

void SieveScriptData::BracketComment::parse()
{
}


// hash-comment = "#" *octet-not-crlf CRLF
SieveScriptData::HashComment::HashComment( Production * p )
    : SieveScriptData::Production( p, "hashcomment" )
{
    require( "#" );
    int e = source().find( "\r\n" );
    if ( e < 0 )
        error( "Comment not terminated" );
    pos() = e + 2;
}

void SieveScriptData::HashComment::parse()
{
}


// identifier = (ALPHA / "_") *(ALPHA / DIGIT / "_")
SieveScriptData::Identifier::Identifier( Production * p )
    : SieveScriptData::Production( p, "identifier" )
{
    const ::String & s = source();
    uint & i = pos();
    uint b = i;

    char c = s[i];
    if ( ! ( ( c >= 'a' && c <= 'z' ) ||
             ( c >= 'A' && c <= 'Z' ) ||
             ( c == '_' ) ) )
        error( "Identifier did not start with a-z or _" );

    while ( ( c >= 'a' && c <= 'z' ) ||
            ( c >= 'A' && c <= 'Z' ) ||
            ( c >= '0' && c <= '9' ) ||
            ( c == '_' ) )
        c = s[++i];

    identifier = s.mid( b, i-b );
}

void SieveScriptData::Identifier::parse()
{
}


// number = 1*DIGIT [ QUANTIFIER ]
SieveScriptData::Number::Number( Production * p )
    : SieveScriptData::Production( p, "number" )
{
    const ::String & s = source();
    uint & i = pos();
    uint b = i;

    char c = s[i];
    while ( c >= '0' && c <= '9' )
        c = s[++i];

    if ( i == b )
        error( "Expected number" );

    bool ok = true;
    uint number = s.mid( b, i-b ).number( &ok );
    if ( !ok )
        error( "Bad number: " + s.mid( b, i-b ) );

    // QUANTIFIER = "K" / "M" / "G"
    uint scale = 1;
    if ( c == 'k' || c == 'K' )
        scale = 1024;
    else if ( c == 'm' || c == 'M' )
        scale = 1024 * 1024;
    else if ( c == 'g' || c == 'G' )
        scale = 1024 * 1024 * 1024;
    if ( number > UINT_MAX / scale )
        error( "Number " + fn( number ) + " is too large for scale " +
               fn( scale ) );
    number = number * scale;
}

void SieveScriptData::Number::parse()
{
}


// tag = ":" identifier
SieveScriptData::Tag::Tag( Production * p )
    : SieveScriptData::Production( p, "tag" )
{
    if ( nextChar() != ':' )
        error( "Tag must start with ':'" );
    skip( 1 );
    id = new Identifier( this );
}

void SieveScriptData::Tag::parse()
{
}


// white-space = 1*(SP / CRLF / HTAB) / comment
// comment = bracket-comment / hash-comment
SieveScriptData::WhiteSpace::WhiteSpace( Production * p )
    : SieveScriptData::Production( p, "whitespace" )
{
    char c = nextChar();
    switch ( c ) {
    case '#':
        (void)new HashComment( this );
        break;
    case '/':
        (void)new BracketComment( this );
        break;
    case ' ':
    case 13:
    case 9:
        while ( c == 9 || c == 13 || c == ' ' ) {
            skip( 1 );
            if ( c == 13 && nextChar() != 10 )
                error( "CR without LF" );
            c = nextChar();
        }
    default:
        error( "Whitespace expected" );
    }
}

void SieveScriptData::WhiteSpace::parse()
{
}




/*! \class SieveScript sievescript.h

    The SieveScript class knows how to parse a Sieve script and
    remember the rules.
 */


/*! Constructs an empty Sieve script. This may be filled in by
    construcing sieve rules with this script as parent.
*/

SieveScript::SieveScript()
    : Garbage()
{

}
