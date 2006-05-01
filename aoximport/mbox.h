// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MBOX_H
#define MBOX_H

#include "migrator.h"
#include "dirtree.h"


class MboxDirectory
    : public DirectoryTree
{
public:
    MboxDirectory( const String & );

protected:
    bool isMailbox( const String &, struct stat * );
    MigratorMailbox * newMailbox( const String &, uint );
};


class MboxMailbox
    : public MigratorMailbox
{
public:
    MboxMailbox( const String & path, uint );

    MigratorMessage * nextMessage();

private:
    class MboxMailboxData * d;
};


#endif
