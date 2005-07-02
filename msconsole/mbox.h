// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MBOX_H
#define MBOX_H

#include "migrator.h"


class MboxMailbox: public MigratorMailbox
{
public:
    MboxMailbox( const String & path, uint );

    MigratorMessage * nextMessage();

private:
    class MboxMailboxData * d;
};


class MboxDirectory: public MigratorSource
{
public:
    MboxDirectory( const String & path );

    MboxMailbox * nextMailbox();

private:
    class MboxDirectoryData * d;
};


#endif
