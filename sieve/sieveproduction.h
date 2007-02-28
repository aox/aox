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

    void setStringList( class StringList * );
    class StringList * stringList() const;

    void setParsed( bool );
    bool parsed() const;

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

    enum MatchType { Is, Contains, Matches };
    MatchType matchType() const;

    enum AddressPart { Localpart, Domain, All, NoAddressPart };
    AddressPart addressPart() const;

    enum Comparator { IOctet, IAsciiCasemap };
    Comparator comparator() const;

    enum BodyMatchType { Rfc822, Text, SpecifiedTypes };
    BodyMatchType bodyMatchType() const;

    StringList * headers() const;
    StringList * keys() const;
    StringList * envelopeParts() const;
    StringList * contentTypes() const;
    bool sizeOverLimit() const;
    uint sizeLimit() const;

private:
    StringList * takeStringList();
    StringList * takeHeaderFieldList();
    String takeTag();

private:
    class SieveTestData * d;
};


#endif
