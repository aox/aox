// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MH_H
#define MH_H

#include "migrator.h"


class MhMailbox
    : public MigratorMailbox
{
public:
    MhMailbox( const String &, uint );
    MigratorMessage *nextMessage();

private:
    class MhMailboxData *d;
};


class MhDirectory
    : public MigratorSource
{
public:
    MhDirectory( const String & );
    MhMailbox *nextMailbox();

private:
    class MhDirectoryData *d;
};


#endif
