// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONSOLE_H
#define CONSOLE_H

#include "qsplitter.h"

class Console: public QSplitter {
    Q_OBJECT
public:
    Console();

    void keyPressEvent( QKeyEvent * );

private slots:
    void changePane();
    void indicatePane( QWidget * );

private:
    class ConsoleData * d;
};

#endif
