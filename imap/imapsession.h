// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "imapresponse.h"
#include "stringlist.h"
#include "session.h"
#include "list.h"

class Mailbox;
class Message;
class IMAP;


class ImapSession
    : public Session
{
public:
    ImapSession( IMAP *, Mailbox *, bool );
    ~ImapSession();

    void abort();

    IMAP * imap() const;

    void emitUpdates( Transaction * t );

    void recordExpungedFetch( const MessageSet & );

    void ignoreModSeq( int64 );

    void clearExpunged( uint );

    void sendFlagUpdate();

private:
    class ImapSessionData * d;

    void emitFlagUpdates( Transaction * );
};


class ImapExpungeResponse
    : public ImapResponse
{
public:
    ImapExpungeResponse( uint, ImapSession * );

    String text() const;
    void setSent();

private:
    uint u;
};


#endif
