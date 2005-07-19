// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGPANE_H
#define LOGPANE_H

#include <qwidget.h>


class LogPane
    : public QWidget
{
    Q_OBJECT
public:
    LogPane( QWidget * );
    ~LogPane();
};


#endif
