// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PAGE_H
#define PAGE_H

#include "event.h"
#include "string.h"

class Bodypart;
class Message;


class Page
    : public EventHandler
{
public:
    Page( class Link *, class HTTP * );

    enum Type {
        MainPage, LoginForm, LoginData, WebmailMailbox, WebmailMessage,
        WebmailPart, ArchiveMailbox, ArchiveMessage, ArchivePart,
        Favicon, Logout, Compose,
        Error
    };

    bool ready() const;
    String text() const;
    String contentType() const;

    void execute();

    static String textPlain( const String & );
    static String textHtml( const String & );

private:
    void errorPage();
    void loginForm();
    void loginData();
    void mainPage();
    void mailboxPage();
    void messagePage();
    void webmailPartPage();
    void archivePage();
    void archiveMessagePage();
    void archivePartPage();
    void favicon();
    void composePage();
    void logoutPage();

    String bodypart( Message *, Bodypart * );
    String message( Message *, Message * );

    String mailbox( class Mailbox * );

    String jsToggle( const String &, bool, const String &, const String & );

private:
    class PageData * d;
};


#endif
