#ifndef SEARCHEDIT_H
#define SEARCHEDIT_H

#include <qlineedit.h>


class SearchEdit: public QLineEdit
{
public:
    SearchEdit( const QString &, QWidget * );

    QSize sizeHint() const;
};


#endif
