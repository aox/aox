// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PARSER_H
#define PARSER_H


class Class;
class Function;


#include "string.h"


class Parser
{
public:
    Parser( const String & );

    bool atEnd() const;
    uint line() const;

    void step();
    bool lookingAt( const String & );

    void scan( const String & );
    String textUntil( const String & );
    void whitespace();
    String identifier();
    String type();
    String argumentList();
    String word();

private:
    uint simpleIdentifier( uint );
    uint complexIdentifier( uint );
    uint operatorHack( uint );
    uint type( uint );
    uint whitespace( uint );

private:
    String t;
    uint i;
};


#endif
