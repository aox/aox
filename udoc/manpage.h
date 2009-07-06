// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MANPAGE_H
#define MANPAGE_H

#include "estring.h"
#include "list.h"
#include "output.h"


class Function;
class Class;
class Intro;


class ManPage
    : public Garbage
{
public:
    ManPage( const char * );
    ~ManPage();

    static ManPage * current();

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
    void addAuthor();
    void addReferences();
    void endPage();

private:
    bool para;
    int fd;
    EString directory;
    SortedList<EString> references;
};


#endif
