// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SINGLETON_H
#define SINGLETON_H

#include "string.h"

class File;


class Singleton
{
public:
    Singleton( File *, uint, const String & );

    File * file() const;
    uint line() const;

private:
    File * f;
    uint l;
};



#endif
