// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIGRATOR_H
#define MIGRATOR_H

#include "event.h"
#include "injector.h"
#include "ustring.h"
#include "estringlist.h"


class Migrator
    : public EventHandler
{
public:
    enum Mode { Mbox, Cyrus, Mh, Maildir };
    Migrator( Mode );

    void setDestination( const UString & );
    void addSource( const EString & );

    Mailbox * target() const;

    void execute();
    int status() const;

    uint messagesMigrated() const;
    uint mailboxesMigrated() const;
    uint migrators() const;

    static void setVerbosity( uint );
    static uint verbosity();

    static void setErrorCopies( bool );
    static bool errorCopies();

private:
    class MigratorData * d;
};


class MigratorSource
    : public Garbage
{
public:
    MigratorSource();
    virtual ~MigratorSource();

    virtual class MigratorMailbox * nextMailbox() = 0;
};


class MigratorMailbox
    : public Garbage
{
public:
    MigratorMailbox( const EString & );
    virtual ~MigratorMailbox();

    EString partialName();

    virtual class MigratorMessage * nextMessage() = 0;

private:
    EString n;
};


class MigratorMessage
    : public Garbage
{
public:
    MigratorMessage( const EString &, const EString & );
    virtual ~MigratorMessage();

    EString description() const;
    EString original() const;
    const EStringList * flags() const;
    void addFlag( const EString & );

    Injectee * message();

private:
    EString s;
    EString o;
    Injectee * m;
    EStringList f;
};


class MailboxMigrator
    : public EventHandler
{
public:
    MailboxMigrator( class MigratorMailbox *,
                     class Migrator * );

    bool valid() const;
    bool done() const;
    EString error() const;

    void execute();

    uint migrated() const;

private:
    class MailboxMigratorData * d;
};


#endif
