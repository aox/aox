// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "scope.h"
#include "configuration.h"
#include "addresscache.h"
#include "fieldcache.h"
#include "allocator.h"
#include "guilog.h"
#include "log.h"
#include "syslogger.h"
#include "database.h"
#include "console.h"
#include "consoleloop.h"
#include "mailbox.h"

#include <qapplication.h>
#include <qeventloop.h>


/*! \nodoc */

static void breakHere()
{
}


static void errorHandler( QtMsgType t, const char * message )
{
    if ( message && *message ) {
        fprintf( stderr, "%s\n", message );
        Log::Severity s = Log::Info;
        switch ( t ) {
        case QtDebugMsg:
            s = Log::Debug;
            break;
        case QtWarningMsg:
            s = Log::Info;
            break;
        case QtFatalMsg:
            s = Log::Disaster;
            break;
        }
        ::log( message, s );
    }
    if ( t != QtDebugMsg )
        breakHere();
}


static QSize goodDefaultSize()
{
    QWidget * dw = QApplication::desktop();
    uint w = dw->width();
    uint h = dw->height();

    // return a size occupying most of the screen, but leaving a
    // little if there's space, and not going beyong 800*600.

    if ( w > 900 )
        w = 800;
    else if ( w > 400 )
        w = w - 100;

    if ( h > w * 3 / 4 )
        h = w * 3 / 4;
    else if ( h > 400 )
        h = h - 100;
    else if ( h > 300 )
        h = 300;

    return QSize( w, h );
}


int main( int argc, char *argv[] )
{
    qInstallMsgHandler( errorHandler );

    Scope global;

    // typical mailstore crud
    Configuration::setup( "mailstore.conf" );

    // our own event loop, merging qt's and ours
    Allocator::addEternal( new ConsoleLoop, "event loop" );

    Log * l = new Log( Log::General );
    Allocator::addEternal( l, "log object" );
    global.setLog( l );
    Allocator::addEternal( new GuiLog, "log object" );

    Database::setup();
    AddressCache::setup();
    FieldNameCache::setup();
    Configuration::report();
    Mailbox::setup();

    l->log( "Starting up" );
    l->commit();

    // typical Qt crud
    qInstallMsgHandler( errorHandler );
    QApplication * a = new QApplication( argc, argv );
    Allocator::addEternal( a, "main qt application" );
    a->connect( qApp, SIGNAL(lastWindowClosed()),
                qApp, SLOT(quit()) );
    QWidget * w = new Console;
    w->resize( goodDefaultSize() );
    w->show();

    // now do it.
    return a->exec();
}
