// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef IMAP_H
#define IMAP_H

#include "saslconnection.h"
#include "list.h"

class EString;
class Command;
class Mailbox;
class ImapSession;
class MailboxGroup;


class IMAP
    : public SaslConnection
{
public:
    IMAP( int );

    void parse();
    virtual void react( Event );
    void reserve( Command * );

    enum State { NotAuthenticated, Authenticated, Selected, Logout };
    State state() const;
    void setState( State );

    enum ClientCapability { Condstore, Annotate, Unicode, QResync,
                            NumClientCapabilities };
    bool clientSupports( ClientCapability ) const;
    void setClientSupports( ClientCapability );

    enum ClientBug { NoUnsolicitedResponses, Nat, NumClientBugs };
    bool clientHasBug( ClientBug ) const;
    void setClientBug( ClientBug );

    bool idle() const;

    void setSession( class Session * );

    static void setup();

    List<Command> * commands() const;
    void unblockCommands();

    void sendChallenge( const EString & );
    void setUser( class User *, const EString & );

    void setPrefersAbsoluteMailboxes( bool );
    bool prefersAbsoluteMailboxes() const;

    void respond( class ImapResponse * );
    void emitResponses();

    void addMailboxGroup( MailboxGroup * );
    void removeMailboxGroup( MailboxGroup * );
    MailboxGroup * mostLikelyGroup( Mailbox *, uint );

    class EventMap * eventMap() const;
    void setEventMap( class EventMap * );

    void recordSyntaxError();

    void restartNatDefeater();
    void defeatNat();

private:
    class IMAPData *d;

    void addCommand();
    void runCommands();
    void run( Command * );
};


class IMAPS
    : public IMAP
{
public:
    IMAPS( int );
};


#endif
