// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
