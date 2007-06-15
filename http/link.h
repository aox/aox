// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LINK_H
#define LINK_H

#include "abnfparser.h"
#include "ustring.h"
#include "string.h"
#include "dict.h"


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
    Link();
    Link( const String &, HTTP * );

    enum Type {
        Archive,
        Webmail,
        Favicon,
        Error
    };

    Type type() const;
    void setType( Type );

    bool magic() const;
    void setMagic( bool );

    Mailbox * mailbox() const;
    void setMailbox( Mailbox * );

    uint uid() const;
    void setUid( uint );

    String part() const;
    void setPart( const String & );

    enum Suffix {
        Thread,
        Rfc822,
        Send,
        None
    };

    Suffix suffix() const;
    void setSuffix( Suffix );

    Dict<UString> * arguments() const;
    void addArgument( const String &, const UString & );
    String query() const;

    String canonical() const;
    String original() const;

    WebPage * webPage() const;

    HTTP * server() const;

private:
    class LinkData * d;
    void parse( const String & );
};


#endif
