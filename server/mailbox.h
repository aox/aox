// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOX_H
#define MAILBOX_H

#include "list.h"

class EventHandler;
class Transaction;
class MessageSet;
class Message;
class String;
class Query;


class Mailbox
    : public Garbage
{
    Mailbox( const String & );

public:
    enum Type { Synthetic, Ordinary, Deleted, View };

    String name() const;
    uint id() const;
    void setId( uint ) const;
    uint uidnext() const;
    uint uidvalidity() const;
    int64 nextModSeq() const;

    void setType( Type );
    Type type() const;

    bool synthetic() const;
    bool ordinary() const;
    bool deleted() const;
    bool view() const;

    bool isHome() const;
    uint owner() const;

    void setOwner( uint );
    void setUidnext( uint );
    void setUidvalidity( uint );
    void setNextModSeq( int64 );
    void setDeleted( bool );
    void setUidnextAndNextModSeq( uint, int64 );

    Mailbox * parent() const;
    List< Mailbox > *children() const;
    bool hasChildren() const;

    Mailbox * source() const;
    String selector() const;

    void setSourceUid( uint, uint );
    uint sourceUid( uint ) const;
    MessageSet sourceUids( const MessageSet & ) const;

    static void setup( class EventHandler * = 0 );
    static Mailbox * find( const String &, bool = false );
    static Mailbox * obtain( const String &, bool create = true );
    static Mailbox * closestParent( const String & );

    static Mailbox * root();
    static Mailbox * find( uint );

    static bool validName( const String & );

    bool operator <=( const Mailbox &b ) {
        if ( id() && b.id() )
            return id() <= b.id();
        return name() <= b.name();
    }

    Query * create( class Transaction *, class User * );
    Query * remove( class Transaction * );
    Query * refresh( EventHandler * = 0 );

    void addSession( class Session * );
    void removeSession( class Session * );
    void notifySessions();
    List<class Session> * sessions() const;

    class Threader * threader() const;

private:
    class MailboxData *d;
    friend class MailboxReader;
};


#endif
