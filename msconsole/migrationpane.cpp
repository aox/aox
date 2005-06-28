// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "migrationpane.h"

#include "migrator.h"

#include <qlayout.h>
#include <qpushbutton.h>
#include <qbuttongroup.h>
#include <qradiobutton.h>
#include <qwidgetstack.h>


class MigrationPaneData
{
public:
    MigrationPaneData()
        : serverType( 0 ),
          mbox( 0 ), cyrus( 0 ), mh( 0 ),
          sourceStack( 0 ),
          start( 0 ), abort( 0 ),
          migrator( 0 )
        {
        }

    QButtonGroup * serverType;
    QRadioButton * mbox;
    QRadioButton * cyrus;
    QRadioButton * mh;
    QWidgetStack * sourceStack;
    QPushButton * start;
    QPushButton * abort;
    Migrator * migrator;
};


/*! \class MigrationPane migrationpane.h

    The MigrationPane class provides options to migrate mailbox
    hierchies from other mailstores to Oryx.
*/


MigrationPane::MigrationPane( QWidget * parent )
    : QWidget( parent ), d( new MigrationPaneData )
{
    d->serverType = new QButtonGroup( 2, QButtonGroup::Vertical, this );
    d->serverType->setTitle( tr( "Migrate From:" ) );

    d->mbox = new QRadioButton( tr( "Berkeley Mailbox" ), d->serverType );
    d->cyrus = new QRadioButton( tr( "Cyrus 2.x" ), d->serverType );
    d->mh = new QRadioButton( tr( "MH Directories" ), d->serverType );

    d->sourceStack = new QWidgetStack( this );

    d->migrator = new Migrator( this );

    d->start = new QPushButton( tr( "Migrate" ), this );
    d->abort = new QPushButton( tr( "Abort" ), this );

    QGridLayout * tll = new QGridLayout( this, 3, 2, 6 );

    tll->addWidget( d->serverType, 0, 0 );
    tll->addWidget( d->sourceStack, 0, 1 );
    tll->addMultiCellWidget( d->migrator, 2, 2, 0, 1 );

    QHBoxLayout * buttons = new QHBoxLayout( QBoxLayout::LeftToRight );
    tll->addMultiCellLayout( buttons, 1, 1, 0, 1 );

    buttons->addWidget( d->start );
    buttons->addWidget( d->abort );
    buttons->addStretch( 1 );

    connect( d->start, SIGNAL(clicked()),
             this, SLOT(startMigration()) );
    connect( d->abort, SIGNAL(clicked()),
             this, SLOT(abortMigration()) );

    connect( d->serverType, SIGNAL(clicked(int)),
             this, SLOT(disenablify()) );

    disenablify();
}


/*! Starts the actual migration.

*/

void MigrationPane::startMigration()
{
    disenablify();
}


/*! Aborts a currently running migration, possibly leaving the
    database in a mildly inconsistent state, if transactions have been
    disabled and a message half-injected.
*/

void MigrationPane::abortMigration()
{
    disenablify();
}


/*! Considers the current state of the widgets, and enables, disables
    and raises other widgets to produce a correct and sensible UI.
*/

void MigrationPane::disenablify()
{
    fprintf( stderr, "ugga!\n" );

    bool canSelectSource = true;

    if ( d->migrator->running() ) {
        canSelectSource = false;
    }
    else if ( d->mbox->isOn() ||
              d->cyrus->isOn() ||
              d->mh->isOn() ) {
        d->abort->setEnabled( false );
        d->start->setEnabled( true );
    }
    else {
        d->abort->setEnabled( false );
        d->start->setEnabled( false );
    }

    d->mbox->setEnabled( canSelectSource );
    d->cyrus->setEnabled( canSelectSource );
    d->mh->setEnabled( canSelectSource );
}
