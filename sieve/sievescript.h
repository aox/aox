// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVESCRIPT_H
#define SIEVESCRIPT_H

#include "sieveproduction.h"

#include "string.h"


class SieveScript
    : public SieveProduction
{
public:
    SieveScript();

    void parse( const String & );
    String parseErrors() const;
    String source() const;

    bool isEmpty() const;

private:
    String location( uint ) const;

private:
    class SieveScriptData * d;
};


#endif
