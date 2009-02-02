// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POSTSCRIPT_H
#define POSTSCRIPT_H

#include "estring.h"

#include "output.h"


class Function;
class Class;
class Intro;
class File;


class Postscript
    : public Garbage
{
public:
    Postscript( const char * );
    ~Postscript();

    static Postscript * current();

    void startHeadline( Intro * );
    void startHeadline( Class * );
    void startHeadline( Function * );
    void endParagraph();
    void addText( const EString & );
    void addArgument( const EString & );
    void addFunction( const EString &, Function * );
    void addClass( const EString &, Class * );

private:
    void output( const EString & );

private:
    File * file;
    EString para;
};


#endif
