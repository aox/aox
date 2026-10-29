// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef JSON_H
#define JSON_H

#include "global.h"
#include "estring.h"
#include "ustring.h"
#include "list.h"


class EStringList;


class Json
    : public Garbage
{
public:
    enum Type { Null, Boolean, Number, String, Array, Object };

    Json( Type );

    static Json * parse( const EString &, EString & error );

    Type type() const;
    bool valid( Type ) const;

    bool boolean() const;
    int64 number() const;
    UString string() const;
    EString ascii() const;

    List<Json> * array() const;
    Json * member( const EString & ) const;
    EStringList * members() const;

    void append( Json * );
    void insert( const EString &, Json * );
    void setBoolean( bool );
    void setNumber( int64 );
    void setString( const UString & );
    void setString( const EString & );

    static Json * object();
    static Json * list();
    static Json * number( int64 );
    static Json * boolean( bool );
    static Json * string( const UString & );
    static Json * string( const EString & );

    EString write() const;

private:
    class JsonData * d;
};


#endif
