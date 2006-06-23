// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MAILDIR_H
#define MAILDIR_H

#include "migrator.h"
#include "dirtree.h"


class MaildirDirectory
    : public DirectoryTree
{
public:
    MaildirDirectory( const String & );

protected:
    bool isMailbox( const String &, struct stat * );
    MigratorMailbox * newMailbox( const String &, uint );
};


class MaildirMailbox
    : public MigratorMailbox
{
public:
    MaildirMailbox( const String &, uint );
    MigratorMessage *nextMessage();

private:
    void readSubDir( const String & );
    
    class MaildirMailboxData *d;
};


#endif
