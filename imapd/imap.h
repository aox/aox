// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef IMAP_H
#define IMAP_H

#include "connection.h"

class String;
class Command;
class ImapSession;
class User;


class IMAP
    : public Connection
{
public:
    IMAP( int );

    void parse();
    void react( Event );
    void reserve( Command * );

    enum State { NotAuthenticated, Authenticated, Selected, Logout };
    State state() const;
    void setState( State );

    bool idle() const;
    void setIdle( bool );

    User * user() const;
    void authenticated( User * );

    void beginSession( ImapSession * );
    ImapSession *session() const;
    void endSession();

    String mailboxName( const String & ) const;

    static void setup();
    bool supports( const String & ) const;

    uint activeCommands() const;
    void unblockCommands();

private:
    class IMAPData *d;

    void addCommand();
    void runCommands();
    void expireCommands();
    void run( Command * );
};


class IMAPS
    : public IMAP
{
public:
    IMAPS( int );

    void finish();

private:
    class IMAPSData * d;
};


#endif
