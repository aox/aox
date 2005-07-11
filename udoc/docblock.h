// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DOCBLOCK_H
#define DOCBLOCK_H

#include "string.h"
#include "dict.h"

class File;
class Class;
class Function;
class Intro;


class DocBlock
    : public Garbage
{
public:
    DocBlock( File *, uint, const String &, Function * );
    DocBlock( File *, uint, const String &, Class * );
    DocBlock( File *, uint, const String &, Intro * );

    bool isClass() const;
    bool isEnum() const;

    String text() const;

    void generate();

    enum State {
        Plain,
        Argument,
        Introduces
    };

private:
    void whitespace( uint &, uint & );
    void word( uint &, uint, uint );
    void overload( uint, uint );
    void plainWord( const String &, uint );
    void checkEndState( uint );
    void setState( State, const String &, uint );
    void generateFunctionPreamble();
    void generateClassPreamble();
    void generateIntroPreamble();

private:
    File * file;
    uint line;
    Class * c;
    Function * f;
    Intro * i;
    String t;
    State s;
    Dict<void> arguments;
    bool isReimp;
    bool introduces;
};


#endif
