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
    void authenticated( uint, const String & );

    void beginSession( Mailbox *, bool );
    ImapSession *session() const;
    void endSession();

    String mailboxName( const String & );

    static void setup();
    bool supports( const String & ) const;

private:
    class IMAPData *d;

    void addCommand();
    void runCommands();
};

#endif
