// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    void remove( Mailbox * );

    uint hits() const;
    uint count() const;

    List<Mailbox> * contents() const;

private:
    class MailboxGroupData * d;
};


#endif
