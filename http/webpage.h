// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "event.h"


class WebPage
    : public EventHandler
{
public:
    WebPage( class HTTP * );

    void execute();

    void addComponent( class PageComponent * );

private:
    class WebPageData * d;
};


class BodypartPage
    : public WebPage
{
public:
    BodypartPage( class Link * );

    void execute();

private:
    class BodypartPageData * d;
};


#endif
