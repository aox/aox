// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef INTRO_H
#define INTRO_H

#include "string.h"
#include "list.h"
#include "class.h"


class DocBlock;


class Intro
    : public Garbage
{
public:
    Intro( const String & );

    void setDocBlock( DocBlock * );
    void addClass( Class * );

    static void output();

    String name() const;

private:
    String n;
    DocBlock * docBlock;
    SortedList<Class> classes;
};

#endif
