// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SEARCHEDIT_H
#define SEARCHEDIT_H

#include <qlineedit.h>


class SearchEdit: public QLineEdit
{
    Q_OBJECT
public:
    SearchEdit( const QString &, QWidget * );
    ~SearchEdit();

    QSize sizeHint() const;

    void focusInEvent( QFocusEvent * );
    void focusOutEvent( QFocusEvent * );
    void keyPressEvent( QKeyEvent * );

    void setFocus();

    bool matches( QWidget * w );

    void changeCurrentMatch( QWidget * w );

public slots:
    void revert();
    void search();
    void ctrls();

private:
    class SearchEditData * d;
};


#endif
