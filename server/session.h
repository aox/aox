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

    uint firstUnseen() const;
    void setFirstUnseen( uint );

    void insert( uint );
    void insert( uint, uint );
    void remove( uint );

    MessageSet recent() const;
    bool isRecent( uint ) const;
    void addRecent( uint );

    const MessageSet & expunged() const;
    const MessageSet & messages() const;

    void expunge( const MessageSet & );
    void clearExpunged();

    uint announced() const;
    void setAnnounced( uint );

    enum ResponseType { New, Modified, Deleted };

    bool responsesNeeded( ResponseType ) const;
    bool responsesReady( ResponseType ) const;
    virtual bool responsesPermitted( Message *, ResponseType ) const;

    void emitResponses();
    void emitResponses( ResponseType );
    virtual void emitExpunge( uint );
    virtual void emitExists( uint );

    List<Message> * modifiedMessages() const;
    void recordChange( List<Message> *, ResponseType );

    virtual void emitModification( Message * );

    void addSessionInitialiser( class SessionInitialiser * );
    void removeSessionInitialiser();

    class SessionData *d;
};


class SessionInitialiser
    : public EventHandler
{
public:
    SessionInitialiser( Session *, EventHandler * );

    bool done() const;
    void execute();

    void addWatcher( EventHandler * );

private:
    class SessionInitialiserData * d;
};


#endif
