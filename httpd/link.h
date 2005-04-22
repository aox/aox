#ifndef LINK_H
#define LINK_H

#include "string.h"

class Link
{
public:
    Link();
    
    void parse( const String & );

    String generate();

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
    void uid();
    void mailbox();
    bool pick( const char * );
    void error( const String & );
    
private:
    class LinkData * d;
};

#endif
