// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
