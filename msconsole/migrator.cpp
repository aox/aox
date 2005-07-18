// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "transaction.h"
#include "allocator.h"
#include "migrator.h"
#include "injector.h"
#include "mailbox.h"
#include "list.h"


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
*/

/*! Constructs an empty

*/

Migrator::Migrator( QWidget * parent )
    : QListView( parent ), d( new MigratorData )
{
    Allocator::addEternal( d, "migrator gcable data" );

    addColumn( tr( "Name" ) );
    addColumn( tr( "Messsages" ) );

    setColumnAlignment( 1, AlignRight );

    setColumnWidthMode( 0, Maximum );
    setColumnWidthMode( 1, Manual );

    setAllColumnsShowFocus( true );

    d->errors = new QListViewItem( this, tr( "Mailboxes with errors" ), "0" );
    d->errors->setExpandable( true );
    d->errors->setOpen( false );
    d->errors->setSelectable( false );

    d->current = new QListViewItem( this,
                                    tr( "Mailboxes being converted" ), "" );
    d->current->setExpandable( true );
    d->current->setOpen( true );
    d->current->setSelectable( false );

    d->done = new QListViewItem( this, tr( "Migrated mailboxes" ), "0" );
    d->done->setExpandable( true );
    d->done->setOpen( false );
    d->done->setSelectable( false );
}


Migrator::~Migrator()
{
    Allocator::removeEternal( d );
}


void Migrator::resizeEvent( QResizeEvent * e )
{
    setColumnWidth( 0, contentsRect().width() - columnWidth( 1 ) );
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
    : Message( rfc822 ), s( desc )
{
    // nothing more
}


/*! Returns a description of the message's source, as set using the
    constructor.
*/

String MigratorMessage::description()
{
    return s;
}


/*! Necessary only to satisfy g++, which wants virtual
    constructors. */

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
    d->source = source;
    refill();
}


/*! Returns true if a Migrator operation is currently running, and
    false otherwise. An operation is running even if there's nothing
    it can do at the moment because of syntax errors or permission
    problems.
*/

bool Migrator::running() const
{
    return false;
}


/*! Fills up the quota of working mailboxes, so we're continuously
    migrating four mailboxes.
*/

void Migrator::refill()
{
    if ( !d->working )
        d->working = new List<MailboxMigrator>;
    List<MailboxMigrator>::Iterator it( d->working );
    while ( it ) {
        if ( it->done() ) {
            QListViewItem * i = it->listViewItem();
            d->current->takeItem( i );
            d->done->insertItem( i );
            d->messagesDone += it->migrated();
            d->done->setText( 1, QString::number( d->messagesDone ) );
            d->working->take( it );
        }
        // skip to next. even if take() does ++it, the code remains
        // correct, because we will eventually discover that all of
        // the working objects are done, even if we don't right now.
        if ( it )
            ++it;
    }
    while ( d->working->count() < 4 ) {
        MigratorMailbox * m = d->source->nextMailbox();
        if ( !m )
            return;
        MailboxMigrator * n = new MailboxMigrator( m, this );
        if ( n->valid() ) {
            d->working->append( n );
            n->createListViewItem( d->current );
            n->execute();
        }
    }
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
          lvi( 0 ),
          mailboxCreator( 0 )
        {}
    MigratorMailbox * source;
    Mailbox * destination;
    Migrator * migrator;
    Message * message;
    bool validated;
    bool valid;
    Injector * injector;
    uint migrated;
    QListViewItem * lvi;
    Transaction * mailboxCreator;
    String error;
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
    Allocator::addEternal( d, "mailbox migrator gcable data" );

    d->source = source;
    d->migrator = migrator;
}


MailboxMigrator::~MailboxMigrator()
{
    Allocator::removeEternal( d );
}


/*! Returns true if this migrator's source contains at least one
    message. Whether the message is syntactically valid is
    irrelevant.

*/

bool MailboxMigrator::valid() const
{
    if ( !d->validated ) {
        d->validated = true;
        d->message = d->source->nextMessage();
        if ( d->message )
            d->valid = true;
    }
    return d->valid;
}


void MailboxMigrator::execute()
{
    if ( d->injector && !d->injector->done() )
        return;

    if ( d->injector && d->injector->failed() ) {
        // record the one that failed somehow XXX
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
            d->migrator->refill();
            return;
        }
        if ( !d->mailboxCreator->done() )
            return;
    }
    else if ( !d->destination ) {
        d->destination = Mailbox::find( d->source->partialName() );
        if ( !d->destination ) {
            d->destination = new Mailbox( d->source->partialName() );
            d->mailboxCreator = d->destination->create( this, 0 );
            // this is slightly wrong: the mailbox owner is set to
            // 0. once we create users as part of the migration
            // process, this needs improvement.
            return;
        }
    }

    if ( d->injector )
        d->message = d->source->nextMessage();
    if ( d->message ) {
        SortedList<Mailbox> * m = new SortedList<Mailbox>;
        m->append( d->destination );
        d->injector = new Injector( d->message, m, this );
        d->injector->execute();
    }
    else {
        d->migrator->refill();
    }
}


/*! Returns true if this message has processed every message in its
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
