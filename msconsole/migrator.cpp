// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "transaction.h"
#include "allocator.h"
#include "migrator.h"
#include "injector.h"
#include "mailbox.h"
#include "scope.h"
#include "list.h"

#include <qlabel.h>
#include <qstyle.h>
#include <qlayout.h>
#include <qtextedit.h>
#include <qapplication.h>


class MigratorData
    : public Garbage
{
public:
    MigratorData()
        : source( 0 ), working( 0 ),
          errors( 0 ), current( 0 ), done( 0 ),
          messagesDone( 0 )
        {}

    MigratorSource * source;
    List<MailboxMigrator> * working;

    QListViewItem * errors;
    QListViewItem * current;
    QListViewItem * done;

    uint messagesDone;
};


/*! \class Migrator migrator.h

    The Migrator class is a list view displaying information about a
    mailbox migration (and managing the migration, too).

    Its API consists of the two functions start() and running(). The
    refill() function does the heavy loading, by ensuring that the
    Migrator always has four MailboxMigrator objects working. (The
    MailboxMigrator objects must call refill() when they're done.)
*/


/*! Constructs an Migrator. start() must be called to supply this
    object with a source.
*/

Migrator::Migrator( QWidget * parent )
    : QListView( parent ), d( new MigratorData )
{
    Allocator::addEternal( d, "migrator gcable data" );

    addColumn( tr( "Name" ) );
    addColumn( tr( "Messages" ) );

    setColumnAlignment( 1, AlignRight );

    setColumnWidthMode( 0, Manual );
    setColumnWidthMode( 1, Manual );

    setAllColumnsShowFocus( true );

    setSorting( -1 );

    d->errors = new QListViewItem( this,
                                   tr( "Mailboxes with errors" ), "0" );
    d->errors->setExpandable( true );
    d->errors->setOpen( true );
    d->errors->setSelectable( false );

    d->current = new QListViewItem( this,
                                    tr( "Mailboxes being converted" ), "" );
    d->current->setExpandable( true );
    d->current->setOpen( true );
    d->current->setSelectable( false );

    d->done = new QListViewItem( this, tr( "Migrated mailboxes" ), "0" );
    d->done->setExpandable( true );
    d->done->setOpen( true );
    d->done->setSelectable( false );
}


Migrator::~Migrator()
{
    Allocator::removeEternal( d );
}


void Migrator::resizeEvent( QResizeEvent * e )
{
    uint sbv = style().pixelMetric( QStyle::PM_ScrollBarExtent );
    setColumnWidth( 0, contentsRect().width() - columnWidth( 1 ) - sbv );
    resizeContents( contentsRect().width(), contentsHeight() );
    QListView::resizeEvent( e );
}



/*! \class MigratorSource migrator.h

    The MigratorSource class models something from which Oryx can
    migrate messages. Each particular server or mailbox format
    provides a subclass.

    The only function is nextMailbox(), which returns a pointer to
    each mailbox within the MigratorSource in turn, and then a null
    pointer.
*/


/*! Constructs a MigratorSource or some kind. Subclasses must do a
    meaningful job.
*/

MigratorSource::MigratorSource()
{
    // what could we possibly need to do?
}


/*! \fn class MigratorMailbox * MigratorSource::nextMailbox()

    Returns a pointer to the next mailbox in this source, or a null
    pointer if all mailboxes have been found.

    It must be possible to call nextMailbox() several times and
    operate on them in parallel. However, unlimited parallelism isn't
    necessary. It's acceptable to hold an open file descriptor in each
    active MigratorMailbox object.

    The results of this function aren't ordered in any way.
*/


/*! \class MigratorMailbox migrator.h

    The MigratorMailbox models a particular mailbox in some other
    mailstore. Each subclass instantiates this to provide a mailbox in
    its format.

    The MigratorSource class provides a sequence of MigratorMailbox
    objects, each of which can be used to provide a sequence of
    MigratorMessage objects.
*/


/*! Constructs a mailbox for \a partialName from which MigratorMessage
    objects can be fetched. Subclasses must do this properly. \a
    partialName will be used for creating a destination mailbox.
*/

MigratorMailbox::MigratorMailbox( const String & partialName )
    : n( partialName )
{
    // nothing
}


/*! Returns the partial name of this mailbox, ie. the name of the
    source mailbox relative to the MigratorSource's top-level name.

    This is typically a file name including all directories that are
    within the directory being migrated.
*/

String MigratorMailbox::partialName()
{
    return n;
}


/*! \class MigratorMessage migrator.h

    The MigratorMessage provides a message and a source. It's used by
    Migrator and MigratorMailbox to generate and inject messages.

    The message is not necessarily valid() - its user must check
    that. During construction all parsing is done, so valid() and
    error() returns their final result as soon as the object has been
    constructed.
*/


/*! Constructs a MigratorMessage for \a rfc822, whose source is
    human-readably described by \a desc.
*/

MigratorMessage::MigratorMessage( const String & rfc822, const String & desc )
    : Message( rfc822 ), s( desc ), o( rfc822 )
{
    // nothing more
}


MigratorMessage::~MigratorMessage()
{
    // nothing necessary
}


/*! Returns a description of the message's source, as set using the
    constructor.
*/

String MigratorMessage::description() const
{
    return s;
}


/*! Returns the raw text used to construct this message. This may
    return the same as rfc822(), but it may also be different: If the
    message couldn't be parsed, rfc2822() return something more or les
    random, while original() returns the original string. If the
    message contained any fixable syntax problems, rfc822() has the
    corrected version, while original() returns the message with these
    problems.
*/

String MigratorMessage::original() const
{
    return o;
}


/*! Necessary only to satisfy g++, which wants virtual
    destructors. */

MigratorSource::~MigratorSource()
{
}


/*! Necessary only to satisfy g++, which wants virtual
    constructors.
*/

MigratorMailbox::~MigratorMailbox()
{
}


/*! Starts migrating data from \a source. Returns immediately, while
    migration probably takes a few minutes or hours. */

void Migrator::start( class MigratorSource * source )
{
    log( "Starting migration" );
    d->source = source;
    refill();
}


/*! Returns true if a Migrator operation is currently running, and
    false otherwise. An operation is running even if there's nothing
    it can do at the moment. As long as there's something it may do in
    the future, it's running.
*/

bool Migrator::running() const
{
    return d->working && !d->working->isEmpty();
}


/*! Fills up the quota of working mailboxes, so we're continuously
    migrating four mailboxes.
*/

void Migrator::refill()
{
    bool lastTaken = false;
    if ( !d->working )
        d->working = new List<MailboxMigrator>;
    List<MailboxMigrator>::Iterator it( d->working );
    while ( it ) {
        List<MailboxMigrator>::Iterator mm( it );
        ++it;
        if ( mm->done() ) {
            QListViewItem * i = mm->listViewItem();
            d->current->takeItem( i );
            d->done->insertItem( i );
            d->messagesDone += mm->migrated();
            d->done->setText( 1, QString::number( d->messagesDone ) );
            d->working->take( mm );
            if ( d->working->isEmpty() )
                lastTaken = true;
        }
    }
    if ( d->working->count() < 4 ) {
        MigratorMailbox * m = d->source->nextMailbox();
        while ( m && d->working->count() < 4 ) {
            if ( m ) {
                MailboxMigrator * n = new MailboxMigrator( m, this );
                if ( n->valid() ) {
                    d->working->append( n );
                    n->createListViewItem( d->current );
                    n->execute();
                }
            }
            m = d->source->nextMailbox();
        }
    }
    if ( lastTaken && d->working->isEmpty() )
        emit done();
}


class MigratorMessageItem
    : public QListViewItem
{
public:
    MigratorMessageItem( QListViewItem *, QListViewItem *,
                         MigratorMessage *, const QString & );
    void activate();
    QString description;
    QString error;
    QString text;
};


MigratorMessageItem::MigratorMessageItem( QListViewItem * parent,
                                          QListViewItem * lastItem,
                                          MigratorMessage * message,
                                          const QString & e )
    : QListViewItem( parent ),
      description( QString::fromLatin1( message->description().cstr() ) ),
      error( QString::fromLatin1( e ) ),
      text( QString::fromLatin1( message->original().cstr() ) )
{
    setMultiLinesEnabled( true );

    setText( 0, description + QString::fromLatin1( "\n" ) + error );
}


void MigratorMessageItem::activate()
{
    QWidget * w = new QWidget( 0, 0, WDestructiveClose );
    QGridLayout * g = new QGridLayout( w, 2, 2, 6 );

    QLabel * l = new QLabel( Migrator::tr( "Message:" ), w );
    g->addWidget( l, 0, 0 );
    l = new QLabel( Migrator::tr( "Error:" ), w );
    g->addWidget( l, 1, 0 );
    l = new QLabel( description, w );
    g->addWidget( l, 0, 1 );
    l = new QLabel( error, w );
    g->addWidget( l, 1, 1 );

    QTextEdit * t = new QTextEdit( w );
    t->setTextFormat( QTextEdit::PlainText );
    t->setReadOnly( true );
    t->setText( text );
    g->addMultiCellWidget( t, 2, 2, 0, 1 );

    // should also have 'mangle' and 'report as error'
    // buttons. 'mangle' should change all ASCII letters to 'x' with
    // certain exceptions. what are the exceptions? letters in the
    // words from, to, subject, content-type, boundary, anything
    // starting with '--', anything containing '=', what more?

    w->show();

    QWidget * tlw = listView()->topLevelWidget();
    w->resize( tlw->width()-20, tlw->height()-20 );
    int w80 = t->fontMetrics().width( "abcd" ) * 20;
    if ( w->width() < w80 && w80 < QApplication::desktop()->width() )
        w->resize( w80, w->height() );
}



class MailboxMigratorData
    : public Garbage
{
public:
    MailboxMigratorData()
        : source( 0 ), destination( 0 ),
          migrator( 0 ),
          message( 0 ),
          validated( false ), valid( false ),
          injector( 0 ),
          migrated( 0 ),
          lvi( 0 ), lastItem( 0 ),
          mailboxCreator( 0 ),
          log( Log::General )
        {}
    MigratorMailbox * source;
    Mailbox * destination;
    Migrator * migrator;
    MigratorMessage * message;
    bool validated;
    bool valid;
    Injector * injector;
    uint migrated;
    QListViewItem * lvi;
    QListViewItem * lastItem;
    Transaction * mailboxCreator;
    String error;
    Log log;
};


/*! \class MailboxMigrator migrator.h

    The MailboxMigrator class takes all the input from a single
    MigratorMailbox, injects it into a single Mailbox, and updates the
    visual representatio of a Migrator.
*/


/*!  Constructs a Migrator to migrate \a source to \a destination and
     show progress on \a migrator.
*/

MailboxMigrator::MailboxMigrator( MigratorMailbox * source,
                                  Migrator * migrator )
    : EventHandler(), d( new MailboxMigratorData )
{
    Scope x( &d->log );

    d->source = source;
    d->migrator = migrator;

    log( "Starting migration of mailbox " + d->source->partialName() );
    commit();
}


/*! Returns true if this migrator's source contains at least one
    message. Whether the message is syntactically valid is
    irrelevant.

*/

bool MailboxMigrator::valid() const
{
    if ( !d->validated ) {
        d->validated = true;
        Scope x( &d->log );
        if ( d->source->partialName().isEmpty() ) {
            log( "Root directory cannot contain messages" );
        }
        else {
            d->message = d->source->nextMessage();
            if ( d->message )
                d->valid = true;
        }
        if ( d->valid )
            log( "Source apparently is a valid mailbox" );
        else
            log( "Source is not a valid mailbox" );
        if ( d->message && d->message->valid() )
            log( "Valid message seen" );
        commit();
    }

    return d->valid;
}


void MailboxMigrator::execute()
{
    if ( d->injector && !d->injector->done() )
        return;

    Scope x( &d->log );

    if ( d->injector && d->injector->failed() ) {
        QString e = QString::fromLatin1( "Database Error: " ) +
                    QString::fromLatin1( d->injector->error().cstr() );
        d->lastItem = new MigratorMessageItem( d->lvi, d->lastItem,
                                               d->message, e );
    }
    else if ( d->injector ) {
        d->migrated++;
        if ( d->lvi )
            d->lvi->setText( 1, QString::number( d->migrated ) );
    }
    else if ( d->mailboxCreator ) {
        if ( d->mailboxCreator->failed() ) {
            d->message = 0;
            d->validated = true;
            d->error = "Error creating " +
                       d->destination->name() +
                       ": " +
                       d->mailboxCreator->error();
            log( d->error, Log::Error );
            commit();
            d->migrator->refill();
            return;
        }
        if ( !d->mailboxCreator->done() )
            return;
    }
    else if ( !d->destination ) {
        d->destination = Mailbox::find( d->source->partialName() );
        if ( !d->destination ) {
            log( "Need to create destination mailbox" );
            d->destination
                = Mailbox::obtain( d->source->partialName(), true );
            d->mailboxCreator = new Transaction( this );
            if ( d->destination &&
                 d->destination->create( d->mailboxCreator, 0 ) == 0 )
            {
                d->mailboxCreator->commit();
            }
            else {
                log( "Unable to migrate " + d->source->partialName() );
                d->migrator->refill();
                d->message = 0;
            }
            return;
        }
    }

    if ( d->injector ) {
        // we've already injected one message. must get another.
        commit();
        d->message = d->source->nextMessage();
    }
    else {
        log( "Ready to start injecting messages" );
    }

    while ( d->message && !d->message->valid() ) {
        Scope x( new Log( Log::General ) );
        log( "Syntax problem: " + d->message->error() );
        log( "Cannot migrate message " + d->message->description() );
        commit();
        QString e = QString::fromLatin1( "Syntax Error: " ) +
                    QString::fromLatin1( d->message->error().cstr() );
        d->lastItem = new MigratorMessageItem( d->lvi, d->lastItem,
                                               d->message, e );
        d->message = d->source->nextMessage();
    }

    if ( d->message ) {
        Scope x( new Log( Log::General ) );
        log( "Starting migration of message " + d->message->description() );
        SortedList<Mailbox> * m = new SortedList<Mailbox>;
        m->append( d->destination );
        d->injector = new Injector( d->message, m, this );
        d->injector->setLog( x.log() );
        d->injector->execute();
    }
    else {
        d->migrator->refill();
    }

    if ( done() )
        commit();
}


/*! Returns true if this mailbox has processed every message in its
    source to completion, and false if there may be something left to
    do.
*/

bool MailboxMigrator::done() const
{
    if ( !d->validated )
        return false;
    if ( d->message )
        return false;
    return true;
}


/*! Creates a QListViewItem describing this migrator as a child of \a
    parent. This function must be called before listViewItem(), and
    can be called only once.
*/

void MailboxMigrator::createListViewItem( QListViewItem * parent )
{
    String n( d->source->partialName() );
    d->lvi = new QListViewItem( parent,
                                QString::fromLatin1( n.cstr() ),
                                "0" );
    d->lvi->setSelectable( false );
}


/*! Returns a pointer to the item created by createListViewItem(). */

QListViewItem * MailboxMigrator::listViewItem() const
{
    return d->lvi;
}


/*! Returns the number of messages successfully migrated so far. */

uint MailboxMigrator::migrated() const
{
    return d->migrated;
}


/*! If anything wrong happened, this returns a textual error
    message. If all is in order, this returns an empty string.
*/

String MailboxMigrator::error() const
{
    return d->error;
}
