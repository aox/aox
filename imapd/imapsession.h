#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "global.h"
#include "messageset.h"

class Mailbox;
class Message;


class ImapSession {
public:
    ImapSession( Mailbox *, bool );
    ~ImapSession();

    Mailbox *mailbox() const;
    bool readOnly() const;

    uint uid( uint ) const;
    uint msn( uint ) const;
    uint count() const;

    Message * message( uint ) const;

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

private:
    class SessionData *d;
};


#endif
