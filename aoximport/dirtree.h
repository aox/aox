// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DIRTREE_H
#define DIRTREE_H

#include "migrator.h"


class DirectoryTree
    : public MigratorSource
{
public:
    DirectoryTree( const String & );
    MigratorMailbox * nextMailbox();

protected:
    virtual bool isMailbox( const String &, struct stat * ) = 0;
    virtual MigratorMailbox * newMailbox( const String &, uint ) = 0;

private:
    class DirectoryTreeData *d;
};


#endif
