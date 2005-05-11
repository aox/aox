// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOX_H
#define MAILBOX_H

#include "list.h"

class Query;
class String;
class EventHandler;
class Message;
class Fetcher;
class MessageSet;


class Mailbox {
public:
    Mailbox( const String & );

    String name() const;
    uint id() const;
    uint uidnext() const;
    uint uidvalidity() const;
    bool deleted() const;
    bool synthetic() const;
    uint owner() const;

    void setUidnext( uint );
    void setDeleted( bool );

    Mailbox *parent() const;
    List< Mailbox > *children() const;

    Message * message( uint, bool = true ) const;
    void clear();

    static void setup();
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

    Query *create( EventHandler * );
    Query *remove( EventHandler * );

    void refresh();

    void fetchHeaders( const MessageSet &, EventHandler * );
    void fetchBodies( const MessageSet &, EventHandler * );
    void fetchFlags( const MessageSet &, EventHandler * );
    void forget( Fetcher * );

    void addWatcher( EventHandler * );
    void removeWatcher( EventHandler * );

private:
    class MailboxData *d;
    friend class MailboxReader;
};


#endif
