// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILBOXES_H
#define MAILBOXES_H

#include "aoxcommand.h"


class ListMailboxes
    : public AoxCommand
{
public:
    ListMailboxes( StringList * );
    void execute();

private:
    class Query * q;
};


class CreateMailbox
    : public AoxCommand
{
public:
    CreateMailbox( StringList * );
    void execute();

private:
    class CreateMailboxData * d;
};


class DeleteMailbox
    : public AoxCommand
{
public:
    DeleteMailbox( StringList * );
    void execute();

private:
    class DeleteMailboxData * d;
};


#endif
