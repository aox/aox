// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ASCIINUMERIC_H
#define ASCIINUMERIC_H

#include "collation.h"


class AsciiNumeric
    : public Collation
{
public:
    AsciiNumeric();

    bool valid( const UString & ) const;
    bool equals( const UString &, const UString & ) const;
    bool contains( const UString &, const UString & ) const;
    int compare( const UString &, const UString & ) const;
};


#endif
