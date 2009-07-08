// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SINGLETON_H
#define SINGLETON_H

#include "estring.h"

class File;


class Singleton
    : public Garbage
{
public:
    Singleton( File *, uint, const EString & );

    File * file() const;
    uint line() const;

private:
    File * f;
    uint l;
};



#endif
