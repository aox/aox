// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ASCIICASEMAP_H
#define ASCIICASEMAP_H

#include "collation.h"


class AsciiCasemap
    : public Collation
{
public:
    AsciiCasemap();

    bool valid( const UString & ) const;
    bool equals( const UString &, const UString & ) const;
    bool contains( const UString &, const UString & ) const;
    int compare( const UString &, const UString & ) const;
};


#endif
