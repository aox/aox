#ifndef IMAP_H
#define IMAP_H

#include "connection.h"


class String;
class Command;
class Mailbox;


class IMAP : public Connection {
public:
    IMAP(int s);
    ~IMAP();

    void react(Event e);

    void parse();
    void addCommand();
    void runCommands();

    enum State { NotAuthenticated, Authenticated, Selected, Logout };
    State state() const;
    void setState( State );

    bool idle() const;
    void setIdle( bool );

    String login();
    void setLogin( const String & );

    void reserve( Command * );

    void wait( int );

    Mailbox *mailbox();
    void setMailbox( Mailbox * );

private:
    class IMAPData *d;
};

#endif
