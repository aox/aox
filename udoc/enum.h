// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ENUM_H
#define ENUM_H


class Class;
class File;


#include "stringlist.h"


class Enum
    : public Garbage
{
public:
    Enum( Class *, const String &, File *, uint );

    void addValue( const String & );

    StringList * values() const;

private:
    Class * c;
    String n;
    File * f;
    uint l;
    StringList v;
};


#endif
