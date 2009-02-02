// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ERROR_H
#define ERROR_H


class File;


#include "global.h"
#include "estring.h"


class Error
    : public Garbage
{
public:
    Error( File *, uint, const EString & );

    static void report();

    bool operator<=( const Error & ) const;

private:
    void blather();

private:
    File * f;
    uint l;
    EString t;
};


#endif
