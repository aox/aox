#ifndef SEARCHEDIT_H
#define SEARCHEDIT_H

#include <qlineedit.h>


class SearchEdit: public QLineEdit
{
    Q_OBJECT
public:
    SearchEdit( const QString &, QWidget * );

    QSize sizeHint() const;

    void focusInEvent( QFocusEvent * );
    void focusOutEvent( QFocusEvent * );

    void setFocus();

    bool matches( QWidget * w );

    void changeCurrentMatch( QWidget * w );

public slots:
    void revert();
    void search();

private:
    class SearchEditData * d;
};


#endif
