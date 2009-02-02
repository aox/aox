// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "estringlist.h"

#include "output.h"


class Function;
class Class;


class WebPage
    : public Garbage
{
public:
    WebPage( const char * );
    ~WebPage();

    static WebPage * current();

    void startHeadline( Intro * );
    void startHeadline( Class * );
    void startHeadline( Function * );
    void endParagraph();
    void addText( const EString & );
    void addLink( const EString &, const EString & );
    void addArgument( const EString & );
    void addFunction( const EString &, Function * );
    void addClass( const EString &, Class * );

private:
    void output( const EString & );
    EString anchor( Function * );
    void endPage();
    void startPage( const EString &, const EString & );

private:
    EString para;
    int fd;
    EString directory;
    EString fn;
    EStringList names;
    bool pstart;
};


#endif
