// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CONSOLE_H
#define CONSOLE_H

#include "qwidget.h"

class Console: public QWidget {
    //Q_OBJECT
public:
    Console();

private:
    class ConsoleData * d;
};

#endif
