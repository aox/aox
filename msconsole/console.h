// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONSOLE_H
#define CONSOLE_H

#include "qwidget.h"

class Console: public QWidget {
    Q_OBJECT
public:
    Console();
    ~Console();

    void keyPressEvent( QKeyEvent * );

    void resizeEvent( QResizeEvent * );

private slots:
    void changePane();
    void indicatePane( QWidget * );

private:
    class ConsoleData * d;
};

#endif
