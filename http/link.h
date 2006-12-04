// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LINK_H
#define LINK_H

#include "abnfparser.h"
#include "string.h"


class HTTP;
class WebPage;
class Mailbox;


class LinkParser
    : public AbnfParser
{
public:
    LinkParser( const String & );
    String pathComponent();
    char character();
};


class Link
    : public Garbage
{
public:
    Link( HTTP * );
    Link( const String &, HTTP * );

    bool valid() const;

    enum Type {
        Archive,
        Webmail,
        Favicon,
        Error
    };

    Type type() const;
    void setType( Type );

    Mailbox * mailbox() const;
    void setMailbox( Mailbox * );

    uint uid() const;
    void setUid( uint );

    String part() const;
    void setPart( const String & );

    String originalURL() const;
    String canonicalURL() const;

    WebPage * webPage() const;

    HTTP * server() const;

private:
    class LinkData * d;
    void parse( const String & );
};


#endif
