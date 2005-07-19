// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "migrationpane.h"

#include "allocator.h"
#include "migrator.h"

#include "mh.h"
#include "mbox.h"
#include "cyrus.h"

#include <qlayout.h>
#include <qgroupbox.h>
#include <qlineedit.h>
#include <qvalidator.h>
#include <qpushbutton.h>
#include <qbuttongroup.h>
#include <qradiobutton.h>
#include <qwidgetstack.h>


static const char * pathRegExp = "^(/[^/]+)+$";


class MigrationPaneData
{
public:
    MigrationPaneData()
        : serverType( 0 ),
          mbox( 0 ), cyrus( 0 ), mh( 0 ),
          sourceStack( 0 ),
          mboxRoot( 0 ),
          cyrusRoot( 0 ),
          mhRoot( 0 ),
          start( 0 ), abort( 0 ),
          migrator( 0 )
        {
        }

    QButtonGroup * serverType;
    QRadioButton * mbox;
    QRadioButton * cyrus;
    QRadioButton * mh;
    QWidgetStack * sourceStack;
    QLineEdit * mboxRoot;
    QLineEdit * cyrusRoot;
    QLineEdit * mhRoot;
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
    Allocator::addEternal( d, "migration pane gcable data" );

    d->serverType = new QButtonGroup( 2, QButtonGroup::Vertical, this );
    d->serverType->setTitle( tr( "Migrate From:" ) );

    d->mbox = new QRadioButton( tr( "Berkeley Mailbox" ), d->serverType );
    d->cyrus = new QRadioButton( tr( "Cyrus 2.x" ), d->serverType );
    d->mh = new QRadioButton( tr( "MH Directories" ), d->serverType );

    d->sourceStack = new QWidgetStack( this );

    addMboxConfiguration();
    addCyrusConfiguration();
    addMHConfiguration();

    connect( d->serverType, SIGNAL(clicked(int)),
             d->sourceStack, SLOT(raiseWidget(int)) );

    d->start = new QPushButton( tr( "&Migrate" ), this );
    d->abort = new QPushButton( tr( "Abort" ), this );

    d->migrator = new Migrator( this );

    QGridLayout * tll = new QGridLayout( this, 3, 2, 6 );

    tll->addWidget( d->serverType, 0, 0 );
    tll->addWidget( d->sourceStack, 0, 1 );
    tll->addMultiCellWidget( d->migrator, 2, 2, 0, 1 );

    QBoxLayout * buttons = new QBoxLayout( QBoxLayout::LeftToRight, 6 );
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


MigrationPane::~MigrationPane()
{
    Allocator::removeEternal( d );
}

/*! Starts the actual migration.

*/

void MigrationPane::startMigration()
{
    if ( d->migrator->running() ) {
    }
    else if ( d->mh->isOn() ) {
        d->migrator->start( new MhDirectory( d->mboxRoot->text().latin1() ) );
    }
    else if ( d->mbox->isOn() ) {
        d->migrator->start( new MboxDirectory( d->mboxRoot->text().latin1() ) );
    }
    else if ( d->cyrus->isOn() ) {
        d->migrator->start( new CyrusDirectory( d->cyrusRoot->text().latin1() ) );
    }
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
    bool canSelectSource = true;

    if ( d->migrator->running() ) {
        canSelectSource = false;
    }
    else if ( d->mbox->isOn() ||
              d->cyrus->isOn() ||
              d->mh->isOn() ) {
        d->abort->setEnabled( false );
        if ( d->mbox->isOn() ) {
            if ( d->mboxRoot->hasAcceptableInput() )
                d->start->setEnabled( true );
            else
                d->start->setEnabled( false );
        }
        else if ( d->cyrus->isOn() ) {
            d->start->setEnabled( false );
            if ( d->cyrusRoot->hasAcceptableInput() )
                d->start->setEnabled( true );
            else
                d->start->setEnabled( false );
        }
        else if ( d->mh->isOn() ) {
            if ( d->mhRoot->hasAcceptableInput() )
                d->start->setEnabled( true );
            else
                d->start->setEnabled( false );
        }
    }
    else {
        d->abort->setEnabled( false );
        d->start->setEnabled( false );
    }

    d->mbox->setEnabled( canSelectSource );
    d->cyrus->setEnabled( canSelectSource );
    d->mh->setEnabled( canSelectSource );
}


/*! This has been separated out of the constructor to set up the mbox
    options.
*/

void MigrationPane::addMboxConfiguration()
{
    QGroupBox * w = new QGroupBox( 1, QGroupBox::Vertical, d->sourceStack );
    d->sourceStack->addWidget( w, d->serverType->id( d->mbox ) );
    w->setTitle( tr( "Source Mbox Tree" ) );
    d->mboxRoot = new QLineEdit( w );
    QRegExpValidator * v
        = new QRegExpValidator(  QRegExp( pathRegExp ), d->mboxRoot );
    d->mboxRoot->setValidator( v );
    connect( d->mboxRoot, SIGNAL(textChanged( const QString & )),
             this, SLOT(disenablify()) );
}


/*! This has been separated out of the constructor to set up the Cyrus
    options.
*/

void MigrationPane::addCyrusConfiguration()
{
    QGroupBox * w = new QGroupBox( 1, QGroupBox::Vertical, d->sourceStack );
    d->sourceStack->addWidget( w, d->serverType->id( d->cyrus ) );
    w->setTitle( tr( "Cyrus Partition Directory" ) );
    d->cyrusRoot = new QLineEdit( w );
    QRegExpValidator * v
        = new QRegExpValidator(  QRegExp( pathRegExp ), d->cyrusRoot );
    d->cyrusRoot->setValidator( v );
    connect( d->cyrusRoot, SIGNAL(textChanged( const QString & )),
             this, SLOT(disenablify()) );
}


/*! This has been separated out of the constructor to set up the MH
    options.
*/

void MigrationPane::addMHConfiguration()
{
    QGroupBox * w = new QGroupBox( 1, QGroupBox::Vertical, d->sourceStack );
    d->sourceStack->addWidget( w, d->serverType->id( d->mh ) );
    w->setTitle( tr( "MH Directory" ) );
    d->mhRoot = new QLineEdit( w );
    QRegExpValidator * v
        = new QRegExpValidator(  QRegExp( pathRegExp ), d->mhRoot );
    d->mhRoot->setValidator( v );
    connect( d->mhRoot, SIGNAL(textChanged( const QString & )),
             this, SLOT(disenablify()) );
}

