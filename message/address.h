// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ADDRESS_H
#define ADDRESS_H

#include "string.h"
#include "list.h"


class Address
{
public:
    Address();
    Address( const String &, const String &, const String & );
    Address( const Address & );
    ~Address();

    Address &operator=( const Address & );

    enum Type { Normal, Bounce, EmptyGroup, Invalid };
    Type type() const;

    uint id() const;
    void setId( uint );

    String name() const;
    String localpart() const;
    String domain() const;

    String toString() const;

    bool valid() const { return type() != Invalid; }

    void setName( const String & );

    static void uniquify( List<Address> * );

private:
    class AddressData * d;

    void init( const String &, const String &, const String & );
};


class AddressParser
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
    String phrase( int & );
    String localpart( int & );
    String atom( int & );
    static String unqp( const String & );

    void error( const char *, int );

    void add( String, const String &, const String & );

    class AddressParserData * d;
};


#endif
