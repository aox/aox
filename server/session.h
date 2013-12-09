// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SESSION_H
#define SESSION_H

#include "global.h"
#include "integerset.h"
#include "permissions.h"
#include "event.h"
#include "list.h"

class Transaction;
class Connection;
class Mailbox;
class Message;
class Select;
class IMAP;


class Session
    : public Garbage
{
public:
    Session( Mailbox *, Connection *, bool );
    virtual ~Session();

    class Connection * connection() const;
    void end();
    virtual void abort();

    bool initialised() const;
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
    uint largestUid() const;

    IntegerSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );
    void addRecent( uint, uint );

    const IntegerSet & expunged() const;
    const IntegerSet & messages() const;

    void expunge( const IntegerSet & );
    virtual void clearExpunged( uint );
    virtual void earlydeletems( const IntegerSet & );

    virtual void emitUpdates( Transaction * );

    IntegerSet unannounced() const;
    void addUnannounced( uint );
    void addUnannounced( const IntegerSet & );
    void clearUnannounced();

    virtual void sendFlagUpdate();

private:
    friend class SessionInitialiser;
    class SessionData *d;
};


class SessionInitialiser
    : public EventHandler
{
public:
    SessionInitialiser( Mailbox *, Transaction * );

    void execute();

private:
    class SessionInitialiserData * d;

    void findSessions();
    void grabLock();
    void releaseLock();
    void findRecent();
    void findMailboxChanges();
    void recordMailboxChanges();
    void recordExpunges();
    void emitUpdates();
    void addToSessions( uint, int64 );
    void submit( class Query * );
};


class SessionPreloader
    : public EventHandler
{
public:
    SessionPreloader( List<Mailbox> *, EventHandler * );

    void execute();
    bool done();

private:
    class SessionPreloaderData * d;
};


#endif
