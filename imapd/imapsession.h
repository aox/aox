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

    Message * message( uint ) const;

    void insert( uint, Message * );
    void remove( uint );

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

    MessageSet expunged() const;

    bool responsesNeeded() const;
    void emitResponses();
    void updateUidnext();

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
