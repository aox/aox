// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVEPRODUCTION_H
#define SIEVEPRODUCTION_H

#include "global.h"
#include "list.h"


class SieveProduction
    : public Garbage
{
public:
    SieveProduction( const char * name );

    void setParent( SieveProduction * );
    SieveProduction * parent() const;

    void setParser( class SieveParser * );

    String name() const;

    void setStart( uint );
    uint start() const;
    void setEnd( uint );
    uint end() const;

    void setError( const String & );
    String error() const;

    void require( const String & );

    static class StringList * supportedExtensions();

private:
    class SieveProductionData * d;
};


class SieveArgument
    : public SieveProduction
{
public:
    SieveArgument();

    void setTag( const String & );
    String tag() const;

    void setNumber( uint );
    uint number() const;

    void setStringList( class UStringList * );
    class UStringList * stringList() const;

    void setParsed( bool );
    bool parsed() const;

    void assertNumber();
    void assertString();
    void assertStringList();
    void assertTag();

private:
    class SieveArgumentData * d;
};


class SieveArgumentList
    : public SieveProduction
{
public:
    SieveArgumentList();

    void append( SieveArgument * );
    List<SieveArgument> * arguments() const;

    void append( class SieveTest * );
    List<class SieveTest> * tests() const;

    SieveArgument * argumentFollowingTag( const String & tag );
    class UString takeTaggedString( const String & tag );
    class UStringList * takeTaggedStringList( const String & tag );
    uint takeTaggedNumber( const String & tag );
    SieveArgument * findTag( const String & tag ) const;
    void allowOneTag( const char *, const char *, const char * = 0,
                      const char * = 0, const char * = 0 );
    void flagUnparsedAsBad();

    UStringList * takeStringList();
    UString takeString();

    void tagError( const char *, const String & );

private:
    class SieveArgumentListData * d;
};


class SieveBlock
    : public SieveProduction
{
public:
    SieveBlock();

    void append( class SieveCommand * );
    List<class SieveCommand> * commands() const;

private:
    class SieveBlockData * d;
};


class SieveCommand
    : public SieveProduction
{
public:
    SieveCommand();

    void parse( const String & );

    void setIdentifier( const String & );
    String identifier() const;

    void setArguments( SieveArgumentList * );
    SieveArgumentList * arguments() const;

    void setBlock( SieveBlock * );
    SieveBlock * block() const;

    void setRequirePermitted( bool );

    void parseAsAddress( const UString &, const char * );

private:
    class SieveCommandData * d;
};


class SieveTest
    : public SieveProduction
{
public:
    SieveTest();

    void setIdentifier( const String & );
    String identifier() const;

    void setArguments( SieveArgumentList * );
    SieveArgumentList * arguments() const;

    void parse();

    enum MatchType { Is, Contains, Matches, Value, Count };
    MatchType matchType() const;

    enum MatchOperator { None, GT, GE, LT, LE, EQ, NE };
    MatchOperator matchOperator() const;

    enum AddressPart {
        Localpart, Domain, User, Detail, All, NoAddressPart
    };
    AddressPart addressPart() const;

    class Collation * comparator() const;

    enum BodyMatchType { Rfc822, Text, SpecifiedTypes };
    BodyMatchType bodyMatchType() const;

    UStringList * headers() const;
    UStringList * keys() const;
    UStringList * envelopeParts() const;
    UStringList * contentTypes() const;
    bool sizeOverLimit() const;
    uint sizeLimit() const;

private:
    UStringList * takeHeaderFieldList();
    void findComparator();
    void findMatchType();
    void findAddressPart();

private:
    class SieveTestData * d;
};


#endif
