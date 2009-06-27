// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MBOX_H
#define MBOX_H

#include "migrator.h"
#include "dirtree.h"


class MboxDirectory
    : public DirectoryTree
{
public:
    MboxDirectory( const EString & );

protected:
    bool isMailbox( const EString &, struct stat * );
    MigratorMailbox * newMailbox( const EString &, uint );
};


class MboxMailbox
    : public MigratorMailbox
{
public:
    MboxMailbox( const EString & path, uint );

    MigratorMessage * nextMessage();

private:
    class MboxMailboxData * d;
};


#endif
