#ifndef PAGE_H
#define PAGE_H

#include "string.h"

class Page
{
public:
    Page( class Link *, class HTTP * );

    String text() const;

    void checkAccess();
    void fetchMailbox();
    void fetchMessage();

    bool ready() const;

private:
    class PageData * d;
};

#endif
