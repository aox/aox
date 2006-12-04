// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "event.h"


class HTTP;
class PageComponent;


class WebPage
    : public EventHandler
{
public:
    WebPage( HTTP * );

    void execute();

    void addComponent( PageComponent * );

private:
    class WebPageData * d;
};


#endif
