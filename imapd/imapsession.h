#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "global.h"

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

private:
    class SessionData *d;
};


#endif
