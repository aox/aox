// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PERMISSIONS_H
#define PERMISSIONS_H

#include "event.h"


class Permissions
    : public EventHandler
{
public:
    Permissions( class Mailbox *, class User *,
                 class EventHandler * );

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
        Admin, // a
        // New rights go above this line.
        NumRights
    };

    bool ready();
    void execute();
    bool allowed( Right );

private:
    class PermissionData *d;
};


#endif
