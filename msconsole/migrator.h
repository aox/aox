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
    ~Migrator();

    void start( class MigratorSource * );

    bool running() const;
    void refill();

    void resizeEvent( QResizeEvent * );

signals:
    void done();

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


class MigratorMessage: public Message
{
public:
    MigratorMessage( const String &, const String & );

    String description() const;
    String original() const;

private:
    String s;
    String o;
};


class MailboxMigrator: public EventHandler
{
public:
    MailboxMigrator( class MigratorMailbox *,
                     class Migrator * );
    virtual ~MailboxMigrator();

    bool valid() const;
    bool done() const;
    String error() const;

    void execute();

    void createListViewItem( QListViewItem * );
    QListViewItem * listViewItem() const;

    uint migrated() const;

private:
    class MailboxMigratorData * d;
};


#endif
