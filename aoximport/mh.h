// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MH_H
#define MH_H

#include "migrator.h"
#include "dirtree.h"


class MhDirectory
    : public DirectoryTree
{
public:
    MhDirectory( const String & );

protected:
    bool isMailbox( const String &, struct stat * );
    MigratorMailbox * newMailbox( const String &, uint );
};


class MhMailbox
    : public MigratorMailbox
{
public:
    MhMailbox( const String &, uint );
    MigratorMessage *nextMessage();

private:
    class MhMailboxData *d;
    void addToSet( const String &, class MessageSet * );
};


#endif
