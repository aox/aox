#ifndef IMAPSESSION_H
#define IMAPSESSION_H

class String;
class Mailbox;
class EventHandler;


class ImapSession {
public:
    ImapSession( const String &, bool, EventHandler * );
    ~ImapSession();

    bool failed() const;
    bool loaded() const;
    Mailbox *mailbox() const;

private:
    class SessionData *d;

    void begin();
    void end();
};


#endif
