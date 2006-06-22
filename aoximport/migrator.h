// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIGRATOR_H
#define MIGRATOR_H

#include "message.h"
#include "event.h"


class Migrator
    : public EventHandler
{
public:
    enum Mode { Mbox, Cyrus, Mh };
    Migrator( Mode );

    void setDestination( const String & );
    void addSource( const String & );

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
    MigratorMailbox( const String & );
    virtual ~MigratorMailbox();

    String partialName();

    virtual class MigratorMessage * nextMessage() = 0;

private:
    String n;
};


class MigratorMessage
    : public Garbage
{
public:
    MigratorMessage( const String &, const String & );
    virtual ~MigratorMessage();

    String description() const;
    String original() const;

    Message * message();

private:
    String s;
    String o;
    Message * m;
};


class MailboxMigrator
    : public EventHandler
{
public:
    MailboxMigrator( class MigratorMailbox *,
                     class Migrator * );

    bool valid() const;
    bool done() const;
    String error() const;

    void execute();

    uint migrated() const;

private:
    class MailboxMigratorData * d;
};


#endif
