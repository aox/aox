#ifndef IMAP_H
#define IMAP_H

#include "connection.h"

class String;
class Command;
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

    uint uid() const;
    String login() const;
    void authenticated( uint, const String & );

    void beginSession( ImapSession * );
    ImapSession *session() const;
    void endSession();

    String mailboxName( const String & ) const;

    static void setup();
    bool supports( const String & ) const;

    uint activeCommands() const;

private:
    class IMAPData *d;

    void addCommand();
    void runCommands();
    void run( Command * );
};

#endif
