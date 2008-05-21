// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SESSION_H
#define SESSION_H

#include "global.h"
#include "messageset.h"
#include "permissions.h"
#include "event.h"
#include "list.h"

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

    void end();

    bool initialised() const;
    void refresh( class EventHandler * );
    bool isEmpty() const;

    Mailbox * mailbox() const;
    bool readOnly() const;

    Permissions *permissions() const;
    void setPermissions( Permissions * );
    bool allows( Permissions::Right );

    uint uidnext() const;
    uint uidvalidity() const;
    void setUidnext( uint );

    int64 nextModSeq() const;
    void setNextModSeq( int64 ) const;

    uint uid( uint ) const;
    uint msn( uint ) const;
    uint count() const;

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

    const MessageSet & expunged() const;
    const MessageSet & messages() const;

    void expunge( const MessageSet & );
    void clearExpunged();

    virtual void emitUpdates();

    MessageSet unannounced() const;
    void addUnannounced( uint );
    void addUnannounced( const MessageSet & );
    void clearUnannounced();

private:
    friend class SessionInitialiser;
    class SessionData *d;
};


class SessionInitialiser
    : public EventHandler
{
public:
    SessionInitialiser( Mailbox * );

    void execute();

private:
    class SessionInitialiserData * d;

    void findSessions();
    void grabLock();
    void releaseLock();
    void findRecent();
    void findUidnext();
    void findViewChanges();
    void writeViewChanges();
    void findMailboxChanges();
    void recordMailboxChanges();
    void recordExpunges();
    void emitUpdates();
    void addToSessions( uint, int64 );
    void submit( class Query * );
};


#endif
