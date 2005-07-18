// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "searchedit.h"

#include "allocator.h"

#include <qaccel.h>
#include <qlabel.h>
#include <qtimer.h>
#include <qbitmap.h>
#include <qpainter.h>
#include <qtooltip.h>
#include <qvariant.h>
#include <qobjectlist.h>
#include <qwidgetlist.h>
#include <qwidgetstack.h>


class SearchEditData
    : public Garbage
{
public:
    SearchEditData(): current( 0 ), frame( 0 ) {}

    QString label;
    QTimer revert;

    QString searchText;
    QWidgetList matches;
    QWidget * current;
    QWidget * frame;
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
    Allocator::addEternal( d, "searchedit gcable data" );

    d->label = t;
    connect( &d->revert, SIGNAL(timeout()),
             this, SLOT(revert()) );
    QAccel * a = new QAccel( this );
    a->insertItem( QKeySequence( CTRL + Key_S ) );
    connect( a, SIGNAL( activated( int ) ),
             this, SLOT( ctrls() ) );
    connect( this, SIGNAL(returnPressed()),
             this, SLOT(search()) );
    connect( this, SIGNAL(textChanged( const QString & )),
             this, SLOT(search()) );

    setFocusPolicy( ClickFocus );
}


SearchEdit::~SearchEdit()
{
    Allocator::removeEternal( d );
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
    if ( text() == d->label )
        clear();
}


/*! This reimplementation helps ensure that the text reverts to
    attract mode after a few seconds. \a f is not used.
*/

void SearchEdit::focusOutEvent( QFocusEvent * f )
{
    if ( d->frame )
        d->frame->hide();
    d->current = 0;
    setText( d->label );
    QLineEdit::focusOutEvent( f );
    d->revert.start( 5000, true );
}


/*! If escape has been pressed, this handler accepts the press and
    moves keybaord focus to the right search result.
*/

void SearchEdit::keyPressEvent( QKeyEvent * ke )
{
    if ( ke->key() == Key_Escape ) {
        ke->accept();
        QWidget * w = d->current;
        if ( w && w->focusProxy() )
            w = w->focusProxy();
        if ( w && w->inherits( "QLabel" ) )
            w = ((QLabel*)w)->buddy();
        if ( w && w->focusPolicy() ) {
            fprintf( stderr, "moving focus to %s/%s\n",
                     w->name(), w->className() );
            w->setFocus();
        }
        return;
    }
    else if ( ( ke->key() == Key_Enter || ke->key() == Key_Return ) &&
              !ke->state() ) {
        ke->accept();
        search();
        return;
    }
    QLineEdit::keyPressEvent( ke );
}


/*! Reverts to attract mode, such that when not in use, the search
    edit does not show a search term.
*/

void SearchEdit::revert()
{
    d->current = 0;
    setText( d->label );
    if ( d->frame )
        d->frame->hide();
}


/*! This reimplementation of the QWidget slot clears the text if focus
    is gained while in attract mode.
*/

void SearchEdit::setFocus()
{
    d->current = 0;
    if ( text() == d->label )
        clear();
    QWidget::setFocus();
}


/*! Searches the entire UI for occurences of the search edit's text,
    and shows them in turn. This never moves focus away from the
    SearchEdit.
*/

void SearchEdit::search()
{
    if ( text() == d->label || text().isEmpty() ) {
        if ( d->frame )
            d->frame->hide();
        d->current = 0;
        return;
    }

    if ( text() == d->searchText ) {
        fprintf( stderr, "stepping to next (of %d)\n", d->matches.count() );
        fprintf( stderr, " - before: %d \n", d->matches.at() );
        QWidget * w = 0;
        if ( d->matches.find( d->current ) >= 0 ) {
            w = d->matches.next();
            if ( !w )
                w = d->matches.first();
        }
        fprintf( stderr, " - after: %d \n", d->matches.at() );
        if ( w )
            changeCurrentMatch( w );
        return;
    }

    d->searchText = text();
    d->matches.clear();

    QObjectList * children = topLevelWidget()->queryList( "QWidget" );
    QObjectListIt it( *children );
    QWidget * w = 0;
    bool seen = false;
    while ( (w=(QWidget*)it.current()) != 0 ) {
        ++it;
        if ( matches( w ) ) {
            d->matches.append( w );
            if ( d->current == w )
                seen = true;
        }
    }
    if ( !seen )
        changeCurrentMatch( d->matches.first() );
}


/*! Returns true if \a w matches the current search criteria, and
    false if not.
*/

bool SearchEdit::matches( QWidget * w )
{
    if ( !w || w == this )
        return false;

    if ( w->inherits( "QLineEdit" ) &&
         ((QLineEdit*)w)->echoMode() != QLineEdit::Normal )
        return false;

    QString s = w->property( "text" ).asString().lower();
    QString l = d->searchText.lower();
    if ( s.find( l ) >= 0 )
        return true;

    s = QToolTip::textFor( w ).lower();
    if ( s.find( l ) >= 0 )
        return true;

    return false;
}


/*! Moves the match indicator to \a w, or hides it if \a w is 0. */

void SearchEdit::changeCurrentMatch( QWidget * w )
{
    if ( !w ) {
        if ( d->frame )
            d->frame->hide();
        d->current = 0;
        return;
    }

    d->current = w;

    if ( !d->frame ) {
        d->frame = new QWidget( topLevelWidget(),
                                "interactive search frame" );
        d->frame->setEraseColor( palette().active().highlight() );
    }

    QPoint tl = w->mapTo( topLevelWidget(), QPoint( -4, -4 ) );
    QBitmap mask( w->width() + 8, w->height() + 8 );
    QPainter p( &mask );
    p.fillRect( 0, 0, mask.width(), mask.height(),
                QBrush( color1 ) );
    p.fillRect( 4, 4, w->width(), w->height(),
                QBrush( color0 ) );
    p.end();
    d->frame->move( tl );
    d->frame->resize( mask.size() );
    d->frame->setMask( mask );
    d->frame->show();
    d->frame->raise();

    while ( w && w->parent() ) {
        if ( w->parent()->inherits( "QWidgetStack" ) )
            ((QWidgetStack*)w->parent())->raiseWidget( w );
        w = w->parentWidget();
    }

}


/*! Handles the ctrl-s press in the manner that seems most natural to
    arnt. This function should not be called except to react to
    ctrl-s. */

void SearchEdit::ctrls()
{
    if ( hasFocus() )
        search();
    else
        setFocus();
}
