// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXGROUP_H
#define MAILBOXGROUP_H

#include "list.h"

class Mailbox;


class MailboxGroup
    : public Garbage
{
public:
    MailboxGroup( List<Mailbox> * );

    bool contains( const Mailbox * );

    uint hits() const;
    uint misses() const;

    List<Mailbox> * contents() const;

private:
    class MailboxGroupData * d;
};


#endif
