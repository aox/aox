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
        
        Production * parent();

        const String name() { return n; }
        const String & source() const;
        uint & pos() const;

        virtual void parse() = 0;

    public:
        uint start;
        Production * mommy;
        SieveScriptData * d;
        ::String n;
    };
    
    template<class T>
    class ProductionList
        : public Production
    {
    public:
        ProductionList( Production * p ) 
            : Production( p, (new T)->name() + "-list" ),
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

    // ADDRESS-PART = ":localpart" / ":domain" / ":all"
    class AddressPart
        : public Production
    {
    public:
        AddressPart( Production * );
        void parse();
    private:
    };

    // argument = string-list / number / tag
    class Argument
        : public Production
    {
    public:
        Argument( Production * );
        void parse();
    private:
    };

    // arguments = *argument [test / test-list]
    class Arguments
        : public Production
    {
    public:
        Arguments( Production * );
        void parse();
    private:
    };

    // block = "{" commands "}"
    class Block
        : public Production
    {
    public:
        Block( Production * );
        void parse();
    private:
    };

    // command = identifier arguments ( ";" / block )
    class Command
        : public Production
    {
    public:
        Command( Production * );
        void parse();
    private:
    };

    // COMPARATOR = ":comparator" string
    class Comparator
        : public Production
    {
    public:
        Comparator( Production * );
        void parse();
    private:
    };

    // MATCH-TYPE = ":is" / ":contains" / ":matches"
    class MatchType
        : public Production
    {
    public:
        MatchType( Production * );
        void parse();
    private:
    };

    // string = quoted-string / multi-line
    class String
        : public Production
    {
    public:
        String( Production * );
        void parse();
    private:
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
    };

    // test-list = "(" test *("," test) ")"
    class X
        : public Production
    {
    public:
        X( Production * );
        void parse();
    private:
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
    : Garbage(), start( 0 ), mommy( 0 ), d( mothership ), n( name )
{
}


SieveScriptData::Production::Production( Production * mother,
                                         ::String name )
    : Garbage(),
      start( mother->start ), mommy( mother ), d( mother->d ), n( name )
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
        

SieveScriptData::Production * SieveScriptData::Production::parent()
{
    return mommy;
}


// ADDRESS-PART = ":localpart" / ":domain" / ":all"
SieveScriptData::AddressPart::AddressPart( Production * p )
    : SieveScriptData::Production( p, "addresspart" )
{
}

void SieveScriptData::AddressPart::parse()
{
}

// argument = string-list / number / tag
SieveScriptData::Argument::Argument( Production * p )
    : SieveScriptData::Production( p, "argument" )
{
}

void SieveScriptData::Argument::parse()
{
}

// arguments = *argument [test / test-list]
SieveScriptData::Arguments::Arguments( Production * p )
    : SieveScriptData::Production( p, ":arguments" )
{
}

void SieveScriptData::Arguments::parse()
{
}

// block = "{" commands "}"
SieveScriptData::Block::Block( Production * p )
    : SieveScriptData::Production( p, "ck" )
{
}

void SieveScriptData::Block::parse()
{
}

// command = identifier arguments ( ";" / block )
SieveScriptData::Command::Command( Production * p )
    : SieveScriptData::Production( p, "ommand" )
{
}

void SieveScriptData::Command::parse()
{
}

// COMPARATOR = ":comparator" string
SieveScriptData::Comparator::Comparator( Production * p )
    : SieveScriptData::Production( p, "::comparator" )
{
}

void SieveScriptData::Comparator::parse()
{
}

// MATCH-TYPE = ":is" / ":contains" / ":matches"
SieveScriptData::MatchType::MatchType( Production * p )
    : SieveScriptData::Production( p, ":matchtype" )
{
}

void SieveScriptData::MatchType::parse()
{
}

// string = quoted-string / multi-line
SieveScriptData::String::String( Production * p )
    : SieveScriptData::Production( p, "ring" )
{
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
    : SieveScriptData::Production( p, "test" )
{
}

void SieveScriptData::Test::parse()
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
