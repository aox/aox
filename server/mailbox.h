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
    uint uidvalidity() const;
    bool deleted() const;
    bool synthetic() const;

    Mailbox *parent() const;
    List< Mailbox > *children() const;

    static void setup();
    static void insert( Mailbox * );
    static Mailbox *find( const String &, bool = false );

private:
    class MailboxData *d;
};


#endif
