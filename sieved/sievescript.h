// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVESCRIPT_H
#define SIEVESCRIPT_H

#include "string.h"


class SieveScript
    : public Garbage
{
public:
    SieveScript();

    void parse( const String & );
    String parseErrors() const;

private:
    String location( uint ) const;

private:
    class SieveScriptData * d;
};


#endif
