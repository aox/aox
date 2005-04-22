#ifndef LINK_H
#define LINK_H

#include "string.h"

class Link
{
public:
    Link();
    Link( class HTTP *, const String & );

    String generate() const;

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

    enum Javascript {
        Enabled,
        Disabled,
        Uncertain,
    };

    Javascript javascript() const;

    String errorMessage() const;

private:
    void parse( const String & );
    void parseUid();
    void parseMailbox();
    bool pick( const String & );
    void error( const String & );
    
private:
    class LinkData * d;
};

#endif
