#ifndef IMAPSESSION_H
#define IMAPSESSION_H

#include "global.h"

class Mailbox;


class ImapSession {
public:
    ImapSession( Mailbox *, bool );
    ~ImapSession();

    Mailbox *mailbox() const;
    bool readOnly() const;

    uint uid( uint ) const;

private:
    class SessionData *d;
};


#endif
