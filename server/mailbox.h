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

    Mailbox *parent() const;
    List< Mailbox > *children() const;

    static void setup();
    static Mailbox *find( const String &, bool = false );
    static void update( const String & );

    bool operator <=( const Mailbox &b ) {
        return id() <= b.id();
    }

private:
    class MailboxData *d;
};


#endif
