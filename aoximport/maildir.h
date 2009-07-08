// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef MAILDIR_H
#define MAILDIR_H

#include "migrator.h"
#include "dirtree.h"


class MaildirDirectory
    : public DirectoryTree
{
public:
    MaildirDirectory( const EString & );

protected:
    bool isMailbox( const EString &, struct stat * );
    MigratorMailbox * newMailbox( const EString &, uint );
};


class MaildirMailbox
    : public MigratorMailbox
{
public:
    MaildirMailbox( const EString &, uint );
    MigratorMessage *nextMessage();

private:
    void readSubDir( const EString & );

    class MaildirMailboxData *d;
};


#endif
