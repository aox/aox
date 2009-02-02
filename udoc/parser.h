// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PARSER_H
#define PARSER_H


class Class;
class Function;


#include "estring.h"


class Parser
    : public Garbage
{
public:
    Parser( const EString & );

    bool atEnd() const;
    uint line();

    void step();
    bool lookingAt( const EString & );

    void scan( const EString & );
    EString textUntil( const EString & );
    void whitespace();
    EString identifier();
    EString type();
    EString argumentList();
    EString word();
    EString value();

private:
    uint simpleIdentifier( uint );
    uint complexIdentifier( uint );
    uint operatorHack( uint );
    uint type( uint );
    uint whitespace( uint );

private:
    EString t;
    uint i;
    uint ln, li;
};


#endif
