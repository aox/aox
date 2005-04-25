// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PAGE_H
#define PAGE_H

#include "event.h"
#include "string.h"


class Page
    : public EventHandler
{
public:
    Page( class Link *, class HTTP * );

    enum Type {
        MainPage, LoginForm, LoginData, WebmailMailbox,
        WebmailMessage, Error
    };

    bool ready() const;
    String text() const;

    void execute();

private:
    void errorPage();
    void loginForm();
    void loginData();
    void mainPage();
    void mailboxPage();
    void messagePage();
    String message( class Message * );

private:
    class PageData * d;
};


#endif
