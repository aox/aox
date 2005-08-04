// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SESSION_H
#define SESSION_H

#include "global.h"
#include "messageset.h"
#include "permissions.h"
#include "event.h"

class Mailbox;
class Message;
class Select;
class IMAP;


class Session
    : public Garbage
{
public:
    Session( Mailbox *, bool );
    virtual ~Session();

    bool initialised() const;
    void refresh( class EventHandler * );

    Mailbox * mailbox() const;
    bool readOnly() const;

    Permissions *permissions() const;
    void setPermissions( Permissions * );
    bool allows( Permissions::Right );

    uint uidnext() const;
    uint uidvalidity() const;

    uint uid( uint ) const;
    uint msn( uint ) const;
    uint count() const;

    uint firstUnseen() const;
    void setFirstUnseen( uint );

    void insert( uint );
    void remove( uint );

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

    const MessageSet & expunged() const;
    const MessageSet & messages() const;

    void setUidnext( uint );
    void expunge( const MessageSet & );

    uint announced() const;
    void setAnnounced( uint );

    bool responsesNeeded() const;
    void emitResponses();
    virtual void emitExpunge( uint );
    virtual void emitExists( uint );

private:
    class SessionData *d;
};


class SessionInitialiser
    : public EventHandler
{
public:
    SessionInitialiser( Session *, EventHandler * );

    bool done() const;
    void execute();

private:
    class SessionInitialiserData * d;
};


#endif
