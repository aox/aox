#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "string.h"

#include "output.h"


class Function;
class Class;


class WebPage
{
public:
    WebPage( const char * );
    ~WebPage();

    static WebPage * current();

    void startHeadline( Class * );
    void startHeadline( Function * );
    void endParagraph();
    void addText( const String & );
    void addArgument( const String & );
    void addFunction( const String &, Function * );
    void addClass( const String &, Class * );

private:
    void output( const String & );
    String anchor( Function * );

private:
    bool para;
    int fd;
    String directory;
    String fn;
};


#endif
