// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MIGRATOR_H
#define MIGRATOR_H

#include <qwidget.h>


class Migrator: public QWidget
{
    Q_OBJECT
public:
    Migrator( QWidget * parent );

    bool running() const;
};

#endif
