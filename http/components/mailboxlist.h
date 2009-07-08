// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MAILBOXLIST_H
#define MAILBOXLIST_H

#include "pagecomponent.h"


class MailboxList
    : public PageComponent
{
public:
    MailboxList();

    void execute();

private:
    class MailboxListData * d;
};


#endif
