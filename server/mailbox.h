// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MAILBOX_H
#define MAILBOX_H

#include "list.h"
#include "ustring.h"

class EventHandler;
class Transaction;
class IntegerSet;
class Message;
class EString;
class Query;


class Mailbox
    : public Garbage
{
    Mailbox( const UString & );

public:
    enum Type { Ordinary, Deleted };

    UString name() const;
    uint id() const;
    void setId( uint ) const;
    uint uidnext() const;
    uint uidvalidity() const;
    int64 nextModSeq() const;
    EString flag() const;

    void setType( Type );
    Type type() const;

    bool ordinary() const;
    bool deleted() const;

    bool isHome() const;
    uint owner() const;

    void setOwner( uint );
    void setUidvalidity( uint );
    void setDeleted( bool );
    void setUidnextAndNextModSeq( uint, int64, Transaction * );
    void setFlag( EString );

    Mailbox * parent() const;
    List< Mailbox > * children() const;
    bool hasChildren() const;

    static void setup( class EventHandler * = 0 );
    static Mailbox * find( const UString &, bool = false );
    static Mailbox * obtain( const UString &, bool create = true );
    static Mailbox * closestParent( const UString & );

    static Mailbox * root();
    static Mailbox * find( uint );

    static uint match( const UString & pattern, uint p,
                       const UString & name, uint n );

    static bool validName( const UString & );

    bool operator <=( const Mailbox &b ) {
        if ( id() && b.id() )
            return id() <= b.id();
        return name() <= b.name();
    }

    Query * create( class Transaction *, class User * );
    Query * remove( class Transaction * );
    static void refreshMailboxes( class Transaction * );

    void abortSessions();
    List<class Session> * sessions() const;

    static bool refreshing();

private:
    class MailboxData * d;
    friend class MailboxReader;
};


#endif
