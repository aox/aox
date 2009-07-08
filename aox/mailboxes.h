// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MAILBOXES_H
#define MAILBOXES_H

#include "aoxcommand.h"


class ListMailboxes
    : public AoxCommand
{
public:
    ListMailboxes( EStringList * );
    void execute();

private:
    class Query * q;
};


class CreateMailbox
    : public AoxCommand
{
public:
    CreateMailbox( EStringList * );
    void execute();

private:
    class CreateMailboxData * d;
};


class DeleteMailbox
    : public AoxCommand
{
public:
    DeleteMailbox( EStringList * );
    void execute();

private:
    class DeleteMailboxData * d;
};


#endif
