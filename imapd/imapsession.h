#ifndef IMAPSESSION_H
#define IMAPSESSION_H

class Mailbox;


class ImapSession {
public:
    ImapSession();

    Mailbox *mailbox() const;
    void setMailbox( Mailbox * );

private:
    class SessionData *d;
};


#endif
