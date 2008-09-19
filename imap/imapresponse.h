// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPRESPONSE_H
#define IMAPRESPONSE_H

#include "session.h"


class ImapResponse
    : public Garbage
{
public:
    ImapResponse( class ImapSession *, const String & );
    ImapResponse( class ImapSession * );
    ImapResponse( IMAP *, const String & );
    ImapResponse( IMAP * );

    bool sent() const;
    virtual void setSent();

    virtual String text() const;

    virtual bool meaningful() const;
    bool changesMsn() const;
    void setChangesMsn();

    Session * session() const;
    IMAP * imap() const;

private:
    class ImapResponseData * d;
};


class ImapByeResponse
    : public ImapResponse
{
public:
    ImapByeResponse( IMAP *, const String & );

    bool meaningful() const;
    void setSent();
};


#endif
