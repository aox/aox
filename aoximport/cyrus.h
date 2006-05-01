// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CYRUS_H
#define CYRUS_H

#include "migrator.h"
#include "dirtree.h"


class CyrusDirectory
    : public DirectoryTree
{
public:
    CyrusDirectory( const String & );

protected:
    bool isMailbox( const String &, struct stat * );
    MigratorMailbox * newMailbox( const String &, uint );
};


class CyrusMailbox
    : public MigratorMailbox
{
public:
    CyrusMailbox( const String &, uint );
    MigratorMessage *nextMessage();

private:
    class CyrusMailboxData *d;
};


#endif
