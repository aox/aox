#ifndef LINK_H
#define LINK_H

#include "string.h"

class Link
{
public:
    Link();
    Link( const String & );

    String string() const;

    enum Type {
        ArchiveMailbox,
        WebmailMailbox,
        Webmail,
        ArchiveMessage,
        WebmailMessage,
        Error
    };

    Type type() const;
    class Mailbox * mailbox() const;
    class Message * message() const;

    String errorMessage() const;

private:
    void parse( const String & );
    void parseUid();
    void parseMailbox();
    void error( const String & );
    String removePrefix();

private:
    class LinkData * d;
};

#endif
