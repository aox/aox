#ifndef MANPAGE_H
#define MANPAGE_H

#include "string.h"
#include "list.h"
#include "output.h"


class Function;
class Class;


class ManPage
{
public:
    ManPage( const char * );
    ~ManPage();

    static ManPage * current();

    void startHeadline( Class * );
    void startHeadline( Function * );
    void endParagraph();
    void addText( const String & );
    void addArgument( const String & );
    void addFunction( const String &, Function * );
    void addClass( const String &, Class * );

private:
    void output( const String & );
    void addAuthor();
    void addReferences();

private:
    bool para;
    int fd;
    String directory;
    SortedList<String> references;
};


#endif
