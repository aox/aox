// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LINK_H
#define LINK_H

#include "string.h"


class Link {
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
    uint uid() const;

    String errorMessage() const;

private:
    void parse( const String & );
    void parseUid( const String * );
    void parseMailbox( const String * );
    void error( const String & );

private:
    class LinkData *d;
};


#endif
