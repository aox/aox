#ifndef MAILBOX_H
#define MAILBOX_H

#include "list.h"

class String;


class Mailbox {
public:
    Mailbox( const String & );

    String name() const;
    uint id() const;
    uint count() const;
    uint uidnext() const;
    uint uidvalidity() const;
    bool deleted() const;
    bool synthetic() const;

    void setUidnext( uint );
    void setDeleted( bool );

    Mailbox *parent() const;
    List< Mailbox > *children() const;

    static void setup();
    static Mailbox *find( const String &, bool = false );
    static Mailbox *obtain( const String &, bool create = true );

    bool operator <=( const Mailbox &b ) {
        if ( id() && b.id() )
            return id() <= b.id();
        return name() <= b.name();
    }

private:
    class MailboxData *d;
};


#endif
