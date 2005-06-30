// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIGRATOR_H
#define MIGRATOR_H

#include <qwidget.h>

#include "message.h"


class Migrator: public QWidget
{
    Q_OBJECT
public:
    Migrator( QWidget * parent );

    void start( class MigratorSource * );

    bool running() const;
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


#endif
