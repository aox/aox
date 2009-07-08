// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SIEVESCRIPT_H
#define SIEVESCRIPT_H

#include "sieveproduction.h"

#include "estring.h"


class SieveScript
    : public SieveProduction
{
public:
    SieveScript();

    void parse( const EString & );
    EString parseErrors() const;
    EString source() const;

    bool isEmpty() const;

    List<SieveCommand> * topLevelCommands() const;

private:
    EString location( uint ) const;

private:
    class SieveScriptData * d;
};


#endif
