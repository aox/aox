#ifndef USERPANE_H
#define USERPANE_H

#include <qwidget.h>


class UserPane: public QWidget
{
    //Q_OBJECT
public:
    UserPane( QWidget * );

private:
    class UserPaneData * d;
};

#endif
