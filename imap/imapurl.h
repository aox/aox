// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPURL_H
#define IMAPURL_H

#include "global.h"
#include "estring.h"
#include "ustring.h"
#include "imapparser.h"


class IMAP;


class ImapUrl
    : public Garbage
{
public:
    ImapUrl( const EString & );
    ImapUrl( const IMAP *, const EString & );

    bool valid() const;
    bool isRump() const;

    EString orig() const;
    EString rump() const;

    class User * user() const;
    EString auth() const;
    EString host() const;
    uint port() const;
    UString mailboxName() const;
    uint uidvalidity() const;
    uint uid() const;
    EString section() const;
    class Date * expires() const;
    EString access() const;
    EString mechanism() const;
    EString urlauth() const;

    void setText( const EString & );
    EString text() const;

private:
    void parse( const EString & );

private:
    class ImapUrlData * d;
};


class ImapUrlParser
    : public ImapParser
{
public:
    ImapUrlParser( const EString &s )
        : ImapParser( s )
    {}

    bool hasIuserauth();
    bool unreserved( char );
    bool escape( char * );
    EString xchars( bool = false );
    bool hostport( EString &, uint * );
    bool hasUid();
    Date * isoTimestamp();
    EString urlauth();
};


#endif
