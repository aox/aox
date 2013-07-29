// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ADDRESS_H
#define ADDRESS_H

#include "estring.h"
#include "list.h"


class UString;


class Address
    : public Garbage
{
public:
    Address();
    Address( const char *, const EString &, const EString & );
    Address( const UString &, const EString &, const EString & );
    Address( const UString &, const UString &, const UString & );
    Address( const EString &, const EString &, const EString & );
    Address( const Address & );

    Address &operator=( const Address & );

    enum Type { Normal, Bounce, EmptyGroup, Local, Invalid };
    Type type() const;

    uint id() const;
    void setId( uint );

    EString name() const;
    UString uname() const;
    UString localpart() const;
    UString domain() const;

    EString lpdomain() const;
    EString toString( bool = false ) const;

    bool valid() const { return type() != Invalid; }

    static void uniquify( List<Address> * );

    bool localpartIsSensible() const;

    void clone( const Address & );

    void setError( const EString & );
    EString error() const;

    bool needsUnicode() const;

private:
    class AddressData * d;

    void init( const UString &, const UString &, const UString & );
};


class AddressParser
    : public Garbage
{
public:
    AddressParser( EString );

    EString error() const;
    List<Address> * addresses() const;

    void assertSingleAddress();

    static AddressParser * references( const EString & );

private:
    void address( int & );
    void space( int & );
    void comment( int & );
    void ccontent( int & );
    EString domain( int & );
    UString phrase( int & );
    EString localpart( int & );
    EString atom( int & );
    static EString unqp( const EString & );
    void route( int & );
    int findBorder( int, int );

    void error( const char *, int );

    void add( UString, const EString &, const EString & );
    void add( const EString &, const EString & );

    class AddressParserData * d;
};


#endif
