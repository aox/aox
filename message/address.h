// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ADDRESS_H
#define ADDRESS_H

#include "string.h"
#include "list.h"


class UString;


class Address
    : public Garbage
{
public:
    Address();
    Address( const UString &, const String &, const String & );
    Address( const String &, const String &, const String & );
    Address( const Address & );
    ~Address();

    Address &operator=( const Address & );

    enum Type { Normal, Bounce, EmptyGroup, Local, Invalid };
    Type type() const;

    uint id() const;
    void setId( uint );

    String name() const;
    UString uname() const;
    String localpart() const;
    String domain() const;

    String toString() const;

    bool valid() const { return type() != Invalid; }

    void setName( const UString & );

    static void uniquify( List<Address> * );

    bool localpartIsSensible() const;

    void clone( const Address & );

    void setError( const String & );
    String error() const;

private:
    class AddressData * d;

    void init( const UString &, const String &, const String & );
};


class AddressParser
    : public Garbage
{
public:
    AddressParser( String );
    ~AddressParser();

    String error() const;
    List<Address> * addresses() const;

    static AddressParser * references( const String & );

private:
    void address( int & );
    void space( int & );
    void comment( int & );
    void ccontent( int & );
    String domain( int & );
    UString phrase( int & );
    String localpart( int & );
    String atom( int & );
    static String unqp( const String & );
    void route( int & );

    void error( const char *, int );

    void add( UString, const String &, const String & );
    void add( const String &, const String & );

    class AddressParserData * d;
};


#endif
