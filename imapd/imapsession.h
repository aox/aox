#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "global.h"

class String;
class Mailbox;
class EventHandler;


class ImapSession {
public:
    ImapSession( Mailbox *, bool, EventHandler * );
    ~ImapSession();

    bool loaded() const;
    Mailbox *mailbox() const;

    uint uid( uint ) const;

private:
    class SessionData *d;

    void begin();
    void end();
};


#endif
