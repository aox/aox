// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOX_H
#define MAILBOX_H

#include "list.h"

class EventHandler;
class Transaction;
class MessageSet;
class Message;
class Fetcher;
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
    void setDeleted( bool );

    Mailbox * parent() const;
    List< Mailbox > *children() const;
    bool hasChildren() const;

    Mailbox * source() const;
    uint sourceUidnext() const;
    String selector() const;

    Message * message( uint, bool = true ) const;
    void clear();

    static void setup( class EventHandler * = 0 );
    static Mailbox * find( const String &, bool = false );
    static Mailbox * obtain( const String &, bool create = true );
    static Mailbox * closestParent( const String & );

    static Mailbox * root();
    static Mailbox * find( uint );

    bool operator <=( const Mailbox &b ) {
        if ( id() && b.id() )
            return id() <= b.id();
        return name() <= b.name();
    }

    Query * create( class Transaction *, class User * );
    Query * remove( class Transaction * );
    Query * refresh();

    void fetchHeaders( const MessageSet &, EventHandler * );
    void fetchTrivia( const MessageSet &, EventHandler * );
    void fetchBodies( const MessageSet &, EventHandler * );
    void fetchFlags( const MessageSet &, EventHandler * );
    void fetchAnnotations( const MessageSet &, EventHandler * );
    void forget( Fetcher * );

    void addWatcher( EventHandler * );
    void removeWatcher( EventHandler * );

private:
    class MailboxData *d;
    friend class MailboxReader;
};


#endif
