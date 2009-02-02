// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CYRUS_H
#define CYRUS_H

#include "migrator.h"
#include "dirtree.h"


class CyrusDirectory
    : public DirectoryTree
{
public:
    CyrusDirectory( const EString & );

protected:
    bool isMailbox( const EString &, struct stat * );
    MigratorMailbox * newMailbox( const EString &, uint );
};


class CyrusMailbox
    : public MigratorMailbox
{
public:
    CyrusMailbox( const EString &, uint );
    MigratorMessage *nextMessage();

private:
    class CyrusMailboxData *d;
};


#endif
