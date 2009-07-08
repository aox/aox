// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef IMAPRESPONSE_H
#define IMAPRESPONSE_H

#include "session.h"


class ImapResponse
    : public Garbage
{
public:
    ImapResponse( class ImapSession *, const EString & );
    ImapResponse( class ImapSession * );
    ImapResponse( IMAP *, const EString & );
    ImapResponse( IMAP * );
    virtual ~ImapResponse() {}

    bool sent() const;
    virtual void setSent();

    virtual EString text() const;

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
    ImapByeResponse( IMAP *, const EString & );

    bool meaningful() const;
    void setSent();
};


#endif
