// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PARSER_H
#define PARSER_H


class Class;
class Function;


#include "string.h"


class Parser
    : public Garbage
{
public:
    Parser( const String & );

    bool atEnd() const;
    uint line();

    void step();
    bool lookingAt( const String & );

    void scan( const String & );
    String textUntil( const String & );
    void whitespace();
    String identifier();
    String type();
    String argumentList();
    String word();
    String value();

private:
    uint simpleIdentifier( uint );
    uint complexIdentifier( uint );
    uint operatorHack( uint );
    uint type( uint );
    uint whitespace( uint );

private:
    String t;
    uint i;
    uint ln, li;
};


#endif
