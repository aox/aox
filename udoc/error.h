#ifndef ERROR_H
#define ERROR_H


class File;


#include "global.h"
#include "string.h"


class Error
{
public:
    Error( File *, uint, const String & );

    static void report();

    bool operator<=( const Error & ) const;

private:
    void blather();

private:
    File * f;
    uint l;
    String t;
};


#endif
