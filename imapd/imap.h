#ifndef IMAP_H
#define IMAP_H

#include "connection.h"

class String;
class Command;
class Mailbox;
class ImapSession;


class IMAP
    : public Connection
{
public:
    IMAP( int );
    ~IMAP();

    void parse();
    void react( Event );
    void reserve( Command * );

    enum State { NotAuthenticated, Authenticated, Selected, Logout };
    State state() const;
    void setState( State );

    bool idle() const;
    void setIdle( bool );

    uint uid();
    String login();
    void setUid( uint );
    void setLogin( const String & );

    void newSession( Mailbox *, bool );
    ImapSession *session() const;
    void endSession();

private:
    class IMAPData *d;

    void addCommand();
    void runCommands();
};

#endif
