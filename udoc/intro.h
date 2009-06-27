// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef INTRO_H
#define INTRO_H

#include "estring.h"
#include "list.h"
#include "class.h"


class DocBlock;


class Intro
    : public Garbage
{
public:
    Intro( const EString & );

    void setDocBlock( DocBlock * );
    void addClass( Class * );

    static void output();

    EString name() const;

private:
    EString n;
    DocBlock * docBlock;
    SortedList<Class> classes;
};

#endif
