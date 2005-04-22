#ifndef PAGE_H
#define PAGE_H

#include "string.h"

class Page
{
public:
    Page( class Link * );

    void setText( const String & );
    String text();

    void checkAccess();
    void fetchMailbox();
    void fetchMessage();

private:
    class PageData * d;
};

#endif
