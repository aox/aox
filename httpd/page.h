#ifndef PAGE_H
#define PAGE_H


#include "event.h"
#include "string.h"


class Page
    : public EventHandler
{
public:
    Page( class Link *, class HTTP * );

    enum Type { MainPage, LoginForm, LoginData, Error };

    bool ready() const;
    String text() const;

    void execute();

private:
    void mainPage();
    void loginForm();
    void loginData();
    void errorPage();

private:
    class PageData * d;
};


#endif
