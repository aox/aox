#ifndef CONSOLE_H
#define CONSOLE_H

#include "qwidget.h"

class Console: public QWidget {
    Q_OBJECT
public:
    Console();

private:
    class ConsoleData * d;
};

#endif
