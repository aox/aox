// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OCTET_H
#define OCTET_H

#include "collation.h"


class Octet
    : public Collation
{
public:
    Octet();

    bool valid( const UString & ) const;
    bool equals( const UString &, const UString & ) const;
    bool contains( const UString &, const UString & ) const;
    int compare( const UString &, const UString & ) const;
};


#endif
