// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MH_H
#define MH_H

#include "migrator.h"
#include "dirtree.h"


class MhDirectory
    : public DirectoryTree
{
public:
    MhDirectory( const EString & );

protected:
    bool isMailbox( const EString &, struct stat * );
    MigratorMailbox * newMailbox( const EString &, uint );
};


class MhMailbox
    : public MigratorMailbox
{
public:
    MhMailbox( const EString &, uint );
    MigratorMessage *nextMessage();

private:
    class MhMailboxData *d;
    void addToSet( const EString &, class IntegerSet * );
};


#endif
