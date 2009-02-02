// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
