// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXGROUP_H
#define MAILBOXGROUP_H

#include "list.h"

class Mailbox;
class IMAP;


class MailboxGroup
    : public Garbage
{
public:
    MailboxGroup( List<Mailbox> *, IMAP * );

    bool contains( const Mailbox * );

    uint hits() const;

    List<Mailbox> * contents() const;

private:
    class MailboxGroupData * d;
};


#endif
