// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "event.h"
#include "permissions.h"


class Mailbox;
class PageComponent;


class WebPage
    : public EventHandler
{
public:
    WebPage( class Link * );

    void execute();

    class Link * link() const;
    class User * user() const;
    class HTTP * server() const;
    class UString parameter( const String & ) const;

    void requireUser();
    void requireRight( Mailbox *, Permissions::Right );
    bool permitted();

    void addComponent( PageComponent *, const PageComponent * = 0 );

    uint uniqueNumber();

private:
    class WebPageData * d;

    String html() const;

    void sendLoginForm();
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


class Rfc822Page
    : public WebPage
{
public:
    Rfc822Page( class Link * );

    void execute();

private:
    class Rfc822PageData * d;
};


#endif
