// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef WEBPAGE_H
#define WEBPAGE_H

#include "event.h"
#include "permissions.h"


class Link;
class EString;
class Mailbox;
class PageComponent;


class WebPage
    : public EventHandler
{
public:
    WebPage( Link * );

    Link * link() const;
    class User * user() const;
    class HTTP * server() const;
    class UString parameter( const EString & ) const;

    virtual void execute();

    void requireUser();
    void requireRight( Mailbox *, Permissions::Right );
    bool permitted();

    void addComponent( PageComponent *, const PageComponent * = 0 );

    void setContents( const EString &, const EString & );

    void finish();
    bool finished() const;

    uint uniqueNumber();

protected:
    EString frontMatter() const;
    EString componentText() const;
    virtual EString contents() const;
    virtual void handleAuthentication();

private:
    class WebPageData * d;
};


class PageFragment
    : public WebPage
{
public:
    PageFragment( Link * );

    EString contents() const;
    void handleAuthentication();
};


class BodypartPage
    : public WebPage
{
public:
    BodypartPage( Link * );
    void execute();

private:
    class BodypartPageData * d;
};


class MessagePage
    : public WebPage
{
public:
    MessagePage( Link * );
    void execute();

private:
    class MessagePageData * d;
};


class StaticBlob
    : public WebPage
{
public:
    StaticBlob( Link * );

    void execute();
};


#endif
