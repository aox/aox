// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "event.h"
#include "permissions.h"


class Mailbox;


class WebPage
    : public EventHandler
{
public:
    WebPage( class Link * );

    void execute();

    void requireRight( Mailbox *, Permissions::Right );
    bool permitted();

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
