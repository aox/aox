// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "global.h"
#include "messageset.h"
#include "event.h"

class Mailbox;
class Message;
class Select;
class IMAP;


class ImapSession {
public:
    ImapSession( Mailbox *, IMAP *, bool );
    ~ImapSession();

    IMAP * imap() const;
    Mailbox * mailbox() const;
    bool readOnly() const;

    uint uidnext() const;
    uint uidvalidity() const;

    uint uid( uint ) const;
    uint msn( uint ) const;
    uint count() const;

    uint firstUnseen() const;
    void setFirstUnseen( uint );

    void insert( uint );
    void remove( uint );

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

    const MessageSet & expunged() const;
    const MessageSet & messages() const;

    bool responsesNeeded() const;
    void emitResponses();
    void updateUidnext();
    void expunge( const MessageSet & );

private:
    class SessionData *d;
};


class ImapSessionInitializer: public EventHandler {
public:
    ImapSessionInitializer( ImapSession *, EventHandler * );

    bool done() const;

    void execute();
private:
    class ImapSessionInitializerData * d;
};


#endif
