// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "searchedit.h"

#include <qtimer.h>
#include <qaccel.h>


class SearchEditData
{
public:
    SearchEditData() {}

    QString label;
    QTimer revert;
};


/*! \class SearchEdit searchedit.h

    This class provides an edit box where changes immediately result
    in interface searches.

    This is a subclass of QLineEdit so it can adjust its sizeHint(),
    displays a "search me! please!" text when it's not being used, and
    does all kinds of fancy things when used.
*/


/*! Constructs an empty search line editor. */

SearchEdit::SearchEdit( const QString & t, QWidget * p )
    : QLineEdit( t, p ), d( new SearchEditData )
{
    d->label = t;
    connect( &d->revert, SIGNAL(timeout()),
             this, SLOT(revert()) );
    QAccel * a = new QAccel( this );
    a->insertItem( QKeySequence( CTRL + Key_S ) );
    connect( a, SIGNAL( activated( int ) ),
             this, SLOT( setFocus() ) );
}


/*! Returns a size which aligns well with QPushButtons. */

QSize SearchEdit::sizeHint() const
{
    QSize s = QLineEdit::sizeHint();
    return QSize( s.width(), s.height()+2 );
}


/*! This reimplementation helps ensure that the text does not revert
    to attract mode while the SearchEdit is being used. \a f is not used.
*/

void SearchEdit::focusInEvent( QFocusEvent * f )
{
    QLineEdit::focusInEvent( f );
    d->revert.stop();
}


/*! This reimplementation helps ensure that the text reverts to
    attract mode after a few seconds. \a f is not used.
*/

void SearchEdit::focusOutEvent( QFocusEvent * f )
{
    QLineEdit::focusOutEvent( f );
    d->revert.start( 5000, true );
}


/*! Reverts to attract mode, such that when not in use, the search
    edit does not show a search term.
*/

void SearchEdit::revert()
{
    deselect();
    setText( d->label );
}


/*! This reimplementation of the QWidget slot clears the text if focus
    is gained while in attract mode.
*/

void SearchEdit::setFocus()
{
    if ( text() == d->label )
        clear();
    QWidget::setFocus();
}
