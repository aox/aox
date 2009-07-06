// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DOCBLOCK_H
#define DOCBLOCK_H

#include "estring.h"
#include "dict.h"

class File;
class Class;
class Function;
class Intro;


class DocBlock
    : public Garbage
{
public:
    DocBlock( File *, uint, const EString &, Function * );
    DocBlock( File *, uint, const EString &, Class * );
    DocBlock( File *, uint, const EString &, Intro * );

    bool isClass() const;
    bool isEnum() const;

    EString text() const;

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
    void plainWord( const EString &, uint );
    void checkEndState( uint );
    void setState( State, const EString &, uint );
    void generateFunctionPreamble();
    void generateClassPreamble();
    void generateIntroPreamble();

private:
    File * file;
    uint line;
    Class * c;
    Function * f;
    Intro * i;
    EString t;
    State s;
    Dict<void> arguments;
    bool isReimp;
    bool introduces;
};


#endif
