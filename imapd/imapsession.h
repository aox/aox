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

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

    bool responsesNeeded() const;
    void emitResponses();

private:
    class SessionData *d;
    friend class ImapSessionInitializer;
};


class ImapSessionInitializer: public EventHandler {
public:
    ImapSessionInitializer( ImapSession *, EventHandler * );

    void execute();
private:
    class ImapSessionInitializerDataExtraLong * d;
};


#endif
