// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "searchedit.h"


/*! \class SearchEdit searchedit.h

    This class provides an edit box where changes immediately result
    in interface searches.

    This is a subclass of QLineEdit so it can adjust its
    sizeHint(). For the moment, it does nothing.
*/


/*! Constructs an empty search line editor. */

SearchEdit::SearchEdit( const QString & t, QWidget * p )
    : QLineEdit( t, p )
{

}


/*! Returns a size which aligns well with QPushButtons. */

QSize SearchEdit::sizeHint() const
{
    QSize s = QLineEdit::sizeHint();
    return QSize( s.width(), s.height()+2 );
}
