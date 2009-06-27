// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DIRTREE_H
#define DIRTREE_H

#include "migrator.h"


class DirectoryTree
    : public MigratorSource
{
public:
    DirectoryTree( const EString & );
    MigratorMailbox * nextMailbox();

protected:
    virtual bool isMailbox( const EString &, struct stat * ) = 0;
    virtual MigratorMailbox * newMailbox( const EString &, uint ) = 0;

private:
    class DirectoryTreeData *d;
};


#endif
