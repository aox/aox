#ifndef IMAPSESSION_H
#define IMAPSESSION_H

class String;
class Mailbox;
class EventHandler;


class ImapSession {
public:
    ImapSession( Mailbox *, bool, EventHandler * );
    ~ImapSession();

    bool loaded() const;
    Mailbox *mailbox() const;

    unsigned int uid( unsigned int ) const;

private:
    class SessionData *d;

    void begin();
    void end();
};


#endif
