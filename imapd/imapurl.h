// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPURL_H
#define IMAPURL_H

#include "global.h"
#include "string.h"


class IMAP;


class ImapUrl
    : public Garbage
{
public:
    ImapUrl( const String & );
    ImapUrl( const IMAP *, const String & );

    bool valid() const;

    class User * user() const;
    String auth() const;
    String host() const;
    uint port() const;
    String mailbox() const;
    uint uidvalidity() const;
    uint uid() const;
    String section() const;
    class Date * expires() const;
    String access() const;
    String mechanism() const;
    String urlauth() const;

    bool isRump() const;

    String orig() const;

private:
    void parse( const String & );

private:
    class ImapUrlData * d;
};


#endif
