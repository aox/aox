// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    EString name() const;

    void setStart( uint );
    uint start() const;
    void setEnd( uint );
    uint end() const;

    void setError( const EString & );
    EString error() const;

    void require( const EString & );

    static class EStringList * supportedExtensions();

    bool ihaveFailed() const;
    void setIhaveFailed();

    EStringList * addedExtensions() const;
    void addExtensions( const EStringList * );

private:
    class SieveProductionData * d;
};


class SieveArgument
    : public SieveProduction
{
public:
    SieveArgument();

    void setTag( const EString & );
    EString tag() const;

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

    SieveArgument * argumentFollowingTag( const EString & tag );
    class UString takeTaggedString( const EString & tag );
    class UStringList * takeTaggedStringList( const EString & tag );
    uint takeTaggedNumber( const EString & tag );
    SieveArgument * findTag( const EString & tag ) const;
    void allowOneTag( const char *, const char *, const char * = 0,
                      const char * = 0, const char * = 0 );

    void numberRemainingArguments();
    UStringList * takeStringList( uint );
    UString takeString( uint );
    uint takeNumber( uint );
    SieveArgument * takeArgument( uint );

    void flagUnparsedAsBad();

    void tagError( const char *, const EString & );

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

    void parse( const EString & );

    void setIdentifier( const EString & );
    EString identifier() const;

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

    void setIdentifier( const EString & );
    EString identifier() const;

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
    UString datePart() const;
    UString dateZone() const;
    bool sizeOverLimit() const;
    uint sizeLimit() const;

private:
    UStringList * takeHeaderFieldList( uint );
    void findComparator();
    void findMatchType();
    void findAddressPart();

private:
    class SieveTestData * d;
};


#endif
