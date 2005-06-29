// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIGRATIONPANE_H
#define MIGRATIONPANE_H

#include <qwidget.h>


class MigrationPane: public QWidget
{
    Q_OBJECT
public:
    MigrationPane( QWidget * );

public slots:
    void startMigration();
    void abortMigration();
    void disenablify();

private:
    class MigrationPaneData * d;
};


#endif
