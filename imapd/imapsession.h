#ifndef IMAPSESSION_H
#define IMAPSESSION_H

class Mailbox;


class ImapSession {
public:
    ImapSession( Mailbox *, bool );
    ~ImapSession();

    Mailbox *mailbox() const;

private:
    class SessionData *d;
};


#endif
