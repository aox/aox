// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef COLLATION_H
#define COLLATION_H

#include "ustring.h"


class Collation
    : public Garbage
{
protected:
    Collation();
    virtual ~Collation();

public:
    virtual bool valid( const UString & ) const = 0;
    virtual bool equals( const UString &, const UString & ) const = 0;
    virtual bool contains( const UString &, const UString & ) const = 0;
    virtual int compare( const UString &, const UString & ) const = 0;

    static Collation * create( const UString & );

    static class EStringList * supported();
};


#endif
