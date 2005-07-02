// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIGRATOR_H
#define MIGRATOR_H

#include <qlistview.h>

#include "message.h"
#include "event.h"


class Migrator: public QListView
{
    Q_OBJECT
public:
    Migrator( QWidget * parent );

    void start( class MigratorSource * );

    bool running() const;
    void refill();

    void resizeEvent( QResizeEvent * );

private:
    class MigratorData * d;
};


class MigratorSource
{
public:
    MigratorSource();
    virtual ~MigratorSource();

    virtual class MigratorMailbox * nextMailbox() = 0;
};


class MigratorMailbox
{
public:
    MigratorMailbox();
    virtual ~MigratorMailbox();

    virtual class MigratorMessage * nextMessage() = 0;
};


class MigratorMessage: public Message
{
public:
    MigratorMessage( const String &, const String & );

    String description();

private:
    class String s;
};


class MailboxMigrator: public EventHandler
{
public:
    MailboxMigrator( class MigratorMailbox *,
                     class Migrator * );

    bool valid() const;
    bool done() const;

    void execute();

private:
    class MailboxMigratorData * d;
};


#endif
