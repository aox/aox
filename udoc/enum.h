// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ENUM_H
#define ENUM_H


class Class;
class File;


#include "estringlist.h"


class Enum
    : public Garbage
{
public:
    Enum( Class *, const EString &, File *, uint );

    void addValue( const EString & );

    EStringList * values() const;

private:
    Class * c;
    EString n;
    File * f;
    uint l;
    EStringList v;
};


#endif
