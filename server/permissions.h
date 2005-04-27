// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PERMISSIONS_H
#define PERMISSIONS_H

#include "event.h"


class Permissions
    : public EventHandler
{
public:
    Permissions( class Mailbox * );

    enum Right {
        Lookup, // l
        Read, // r
        KeepSeen, // s
        Write, // w
        Insert, // i
        Post, // p
        CreateMailboxes, // k
        DeleteMailbox, // x
        DeleteMessages, // t
        Expunge, // e
        Admin // a
    };

    bool ready();
    bool allowed();
    void verify( class User *, Right, class EventHandler * );
    void execute();

private:
    class AclData *d;
};


#endif
