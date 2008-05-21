// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPSESSION_H
#define IMAPSESSION_H

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

    IMAP * imap() const;

    void emitUpdates();

    void recordExpungedFetch( const MessageSet & );

    void enqueue( const String & );

    void addFlags( List<class Flag> *, class Command * );

    void ignoreModSeq( int64 );

private:
    class ImapSessionData * d;

    void emitExpunges();
    void emitUidnext();
    void emitFlagUpdates();
};


#endif
