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

    void emitExpunge( uint );
    void emitModification( Message * );
    void emitExists( uint );
    bool responsesPermitted( Message *, ResponseType ) const;
    bool responsesReady( ResponseType ) const;

    void recordExpungedFetch( const MessageSet & );

    void enqueue( const String & );

    void emitResponses();

    void ignoreModSeq( int64 );

private:
    class ImapSessionData * d;
};


#endif
