// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ACL_H
#define ACL_H


class ACL {
public:
    ACL( class Mailbox * );

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
    bool allowed( class User *, Right );

    void refresh( class EventHandler * );

private:
    class ACLData * d;
};


#endif
