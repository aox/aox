// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef USERPANE_H
#define USERPANE_H

#include <qwidget.h>


class UserPane: public QWidget
{
    Q_OBJECT
public:
    UserPane( QWidget * );

private slots:
    void addAlias();
    void removeAlias();
    void updateExceptLogin();
    void perhapsUpdateLogin();


private:
    class UserPaneData * d;
};

#endif
