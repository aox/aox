// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPURL_H
#define IMAPURL_H

#include "global.h"
#include "string.h"
#include "imapparser.h"


class IMAP;


class ImapUrl
    : public Garbage
{
public:
    ImapUrl( const String & );
    ImapUrl( const IMAP *, const String & );

    bool valid() const;
    bool isRump() const;

    String orig() const;
    String rump() const;

    class User * user() const;
    String auth() const;
    String host() const;
    uint port() const;
    String mailboxName() const;
    uint uidvalidity() const;
    uint uid() const;
    String section() const;
    class Date * expires() const;
    String access() const;
    String mechanism() const;
    String urlauth() const;

    void setText( const String & );
    String text() const;

private:
    void parse( const String & );

private:
    class ImapUrlData * d;
};


class ImapUrlParser
    : public ImapParser
{
public:
    ImapUrlParser( const String &s )
        : ImapParser( s )
    {}

    bool hasIuserauth();
    bool unreserved( char );
    bool escape( char * );
    String xchars( bool = false );
    bool hostport( String &, uint * );
    bool hasUid();
    Date * isoTimestamp();
    String urlauth();
};


#endif
