// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POSTSCRIPT_H
#define POSTSCRIPT_H

#include "string.h"

#include "output.h"


class Function;
class Class;
class File;


class Postscript
{
public:
    Postscript( const char * );
    ~Postscript();

    static Postscript * current();

    void startHeadline( Class * );
    void startHeadline( Function * );
    void endParagraph();
    void addText( const String & );
    void addArgument( const String & );
    void addFunction( const String &, Function * );
    void addClass( const String &, Class * );

private:
    void output( const String & );

private:
    File * file;
    String para;
};


#endif
