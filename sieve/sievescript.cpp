// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sievescript.h"

#include "sievecommand.h"
#include "stringlist.h"



class SieveScriptData
    : public Garbage
{
public:
    SieveScriptData(): Garbage(), pos( 0 ), script( 0 ) {}

    ::String source;
    uint pos;

    class Production
        : public Garbage
    {
    public:
        Production( SieveScriptData * mothership, ::String name );
        Production( Production * inside, ::String name );
        virtual ~Production() {}

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
            typename List<T>::Iterator i( c );
            while ( i ) {
                i->parse();
                ++i;
            }
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

        ::String string() { return identifier; }
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

        uint number() { return n; }
    private:
        uint n;
    };

    // tag = ":" identifier
    class Tag
        : public Production
    {
    public:
        Tag( Production * );
        void parse();

        ::String tag() { return ":" + id->string(); }
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

        ::String string();
        uint number();
        ::String tag();
        ::StringList * stringList();

    private:
        class SieveScriptData::Tag * t;
        class SieveScriptData::Number * n;
        class SieveScriptData::StringList * sl;
    };

    // arguments = *argument [test / test-list]
    class Arguments
        : public Production
    {
    public:
        Arguments( Production * );
        void parse();
        Argument * singleArgument();
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
        SieveScriptData::ProductionList<Command> * block;
    };

    // string = quoted-string / multi-line
    class String
        : public Production
    {
    public:
        String( Production * );
        void parse();

        ::String string() const { return s; }
    private:
        ::String s;
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

        ::StringList * strings() { return l; }

    private:
        ::StringList * l;
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

    class Start
        : public Production
    {
    public:
        Start( SieveScriptData * d );
        void parse();
    private:
        SieveScriptData::ProductionList<Command> * commands;
    };

    Start * script;

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


void SieveScriptData::Production::error( const ::String & message )
{
    if ( !e.isEmpty() )
        return;

    if ( pos() < source().length() )
        bang = pos();
    else
        bang = start;
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
    : SieveScriptData::Production( p, "argument" ), t( 0 ), n( 0 ), sl( 0 )
{
    switch ( nextChar() ) {
    case ':':
        t = new Tag( this );
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
        n = new Number( this );
        break;
    case '[':
    case '"':
    case 't':
    case 'T':
        sl = new StringList( this );
        break;
    default:
        error( "No valid argument seen" );
        break;
    }
}


void SieveScriptData::Argument::parse()
{
}


::String SieveScriptData::Argument::string()
{
    ::StringList * l = stringList();

    if ( l && l->count() == 1 )
        return *l->first();

    if ( !l )
        error( "Needed single-item string list" );
    else if ( l->count() != 1 )
        error( "Expected one string, found list of " +
               fn( l->count() ) + " strings" );
    return "";
}


uint SieveScriptData::Argument::number()
{
    if ( n )
        return n->number();
    else if ( sl )
        error( "Argument is a string (or string list), "
               "but a number is expected" );
    else if ( t )
        error( "Argument is a tag, but a number is expected" );
    else
        error( "Argument is not a number, and must be" );
    return 0;
}


::String SieveScriptData::Argument::tag()
{
    if ( t )
        return t->tag();
    else if ( sl )
        error( "Argument is a string (or string list), "
               "but a tag is expected" );
    else if ( n )
        error( "Argument is a number, but a tag is expected" );
    else
        error( "Argument is not a tag, and must be" );
    return "";
}


StringList * SieveScriptData::Argument::stringList()
{
    if ( sl )
        return sl->strings();
    else if ( t )
        error( "Argument is a tag, but a string (list) is expected" );
    else if ( n )
        error( "Argument is a number, but a string (list) is expected" );
    else
        error( "Argument is not a string, and must be" );
    return 0;
}


// arguments = *argument [test / test-list]
SieveScriptData::Arguments::Arguments( Production * p )
    : SieveScriptData::Production( p, ":arguments" )
{
    arguments = new SieveScriptData::ProductionList<Argument>( this );
    // see TestList below
    testList = 0;
}


void SieveScriptData::Arguments::parse()
{
    // call new TestList( this ); if we do have a testlist
}


SieveScriptData::Argument * SieveScriptData::Arguments::singleArgument()
{
    uint c = arguments->children()->count();
    if ( c == 1 )
        return arguments->children()->first();
    error( "Command needs one argument, but " + fn ( c ) + " present" );
    return 0;
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
    block = new SieveScriptData::ProductionList<Command>( this );
    require( "}" );
}


void SieveScriptData::Command::parse()
{
    SieveCommand * command = 0;
    //bool test = false;
    //bool block = false;
    ::String n = id->string();
    if ( n == "keep" ) {
        command = new SieveCommand( SieveCommand::Keep );
    }
    else if ( n == "reject" ) {
        command = new SieveCommand( SieveCommand::Reject );
    }
    else if ( n == "fileinto" ) {
        command = new SieveCommand( SieveCommand::FileInto );
        Argument * a = args->singleArgument();
        if ( a ) {
            //Mailbox * m = d->user->mailbox( a->string() );
        }
    }
    else if ( n == "redirect" ) {
        command = new SieveCommand( SieveCommand::Keep );
    }
    else if ( n == "discard" ) {
        command = new SieveCommand( SieveCommand::Keep );
    }
    else if ( n == "if" ) {
        command = new SieveCommand( SieveCommand::Keep );
    }
    else if ( n == "require" ) {
        command = new SieveCommand( SieveCommand::Keep );
    }
    else if ( n == "stop" ) {
        command = new SieveCommand( SieveCommand::Keep );
    }
    else {
        error( "Unknown command: " + n );
    }
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
            s.append( "\r\n" );
            break;
        case 10:
            error( "LF without preceding CR" );
            break;
        case '\\':
            skip( 1 );
            if ( nextChar() == 0 || nextChar() == 10 || nextChar() == 13 )
                error( "Can't quote NUL, CR or LF" );
            s.append( nextChar() );
            skip( 1 );
            break;
        case 0: // just plain illegal
            error( "0 byte seen" );
            break;
        default: // other-not-qspecial
            s.append( nextChar() );
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
        s.append( c );
        skip( 1 );
        if ( c == 10 ) {
            error( "LF without CR" );
        }
        else if ( c == 13 ) {
            c = nextChar();
            if ( c != 10 )
                error( "CR without LF" );
            s.append( c );
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
    : SieveScriptData::Production( p, "::stringlist" ), l( new ::StringList )
{
    switch ( nextChar() ) {
    case '[':
        if ( present( "[" ) ) {
            l->append( (new String( this ))->string() );
            while ( present( "," ) )
                l->append( (new String( this ))->string() );
            require( "]" );
        }
        break;
    case '"':
    case 't':
    case 'T':
        l->append( (new String( this ))->string() );
        break;
    default:
        error( "string-list expected" );
        break;
    }
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
    n = s.mid( b, i-b ).number( &ok );
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
    if ( n > UINT_MAX / scale )
        error( "Number " + fn( n ) + " is too large when scaled by " +
               fn( scale ) );
    n = n * scale;
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


SieveScriptData::Start::Start( SieveScriptData * d )
    : Production( d, "Start" ), commands( 0 )
{
    commands = new SieveScriptData::ProductionList<Command>( this );
}


void SieveScriptData::Start::parse()
{
    commands->parse();
}


/*! Parses \a script and stores the script as this object. Any
    previous script content is deleted. If \a script is has parse
    errors, they may be accessed as parseErrors().
*/

void SieveScript::parse( const String & script )
{
    d->source = script;
    d->pos = 0;
    d->script = new SieveScriptData::Start( d );
    d->script->parse();
}


/*! Returns a (multi-line) string describing all the parse errors seen
    by the last call to parse(). If there are no errors, the returned
    string is empty. If there are any, it is a multiline string with
    CRLF after each line (including the last).
*/

String SieveScript::parseErrors() const
{
    String errors;
    List<SieveScriptData::Production> unhandled;
    unhandled.append( d->script );
    SieveScriptData::Production * p = unhandled.shift();
    while ( p ) {
        if ( !p->e.isEmpty() ) {
            errors.append( location( p->bang ) );
            errors.append( p->e );
            errors.append( "\r\n" );
            while ( p ) {
                errors.append( location( p->start ) );
                errors.append( ": (Error happened while parsing " );
                errors.append( p->n );
                errors.append( ")\r\n" );
                p = p->mommy;
            }
        }
        p = unhandled.shift();
    }
    return errors;
}


/*! Returns a string describing the location of \a position in the
    current script.
*/

String SieveScript::location( uint position ) const
{
    uint i = 0;
    uint l = 1;
    while ( i < position ) {
        if ( d->source[i] == '\n' )
            l++;
        i++;
    }
    String r = fn( l );
    r.append( ":" );
    r.append( fn( position - i + 1 ) );
    r.append( ":" );
    return r;
}


/*! Returns true if

*/

bool SieveScript::isEmpty() const
{
    return false;
}


/*! Returns a copy of the source code of this script. */

String SieveScript::source() const
{
    return d->source;
}
