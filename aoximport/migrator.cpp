// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "migrator.h"

#include "file.h"
#include "list.h"
#include "flag.h"
#include "timer.h"
#include "scope.h"
#include "mailbox.h"
#include "database.h"
#include "allocator.h"
#include "transaction.h"
#include "recipient.h"
#include "eventloop.h"
#include "injector.h"
#include "dirtree.h"
#include "maildir.h"
#include "cyrus.h"
#include "mbox.h"
#include "utf.h"
#include "mh.h"

#include <stdio.h>
#include <sys/stat.h> // mkdir
#include <sys/types.h> // mkdir
#include <unistd.h> // getpid
#include <time.h> // time


class MigratorData
    : public Garbage
{
public:
    MigratorData()
        : working( 0 ),
          messagesDone( 0 ), mailboxesDone( 0 ),
          mode( Migrator::Mbox ),
          startup( (uint)time( 0 ) )
    {}

    UString destination;
    List< MigratorSource > sources;
    MailboxMigrator * working;

    uint messagesDone;
    uint mailboxesDone;
    Migrator::Mode mode;
    uint startup;
};


/*! \class Migrator migrator.h

    The Migrator class is a list view displaying information about a
    mailbox migration (and managing the migration, too).

    Its API consists of the two functions start() and running(). The
    execute() function does the heavy loading, by ensuring that the
    Migrator always has four MailboxMigrator objects working. (The
    MailboxMigrator objects must call execute() when they're done.)
*/


/*! Constructs a new Migrator for mailboxes of type \a m. */

Migrator::Migrator( Mode m )
    : d( new MigratorData )
{
    d->mode = m;
}


/*! Sets this Migrator's destination to a Mailbox named \a s. */

void Migrator::setDestination( const UString &s )
{
    d->destination = s;
}


/*! Returns this Migrator's destination, as set by setDestination(). */

UString Migrator::destination() const
{
    return d->destination;
}


/*! Creates a MigratorSource object from the string \a s, and adds it to
    this Migrator's list of sources.
*/

void Migrator::addSource( const EString &s )
{
    switch( d->mode ) {
    case Mbox:
        d->sources.append( new MboxDirectory( s ) );
        break;
    case Cyrus:
        d->sources.append( new CyrusDirectory( s ) );
        break;
    case Mh:
        d->sources.append( new MhDirectory( s ) );
        break;
    case Maildir:
        d->sources.append( new MaildirDirectory( s ) );
        break;
    }
}


/*! Finds another mailbox to migrate.
*/

void Migrator::execute()
{
    if ( d->working && d->working->done() ) {
        d->messagesDone += d->working->migrated();
        d->mailboxesDone++;
        d->working = 0;
    }

    while ( !d->working && !d->sources.isEmpty() ) {
        MigratorSource * source = d->sources.first();
        MigratorMailbox * m( source->nextMailbox() );
        if ( m ) {
            MailboxMigrator * n = new MailboxMigrator( m, this );
            if ( n->valid() ) {
                d->working = n;
                n->execute();
                return;
            }
        }
        else {
            d->sources.shift();
        }
    }

    if ( d->working )
        return;

    if ( Database::idle() )
        EventLoop::global()->shutdown();
    else
        Database::notifyWhenIdle( this );
}


/*! \class MigratorSource migrator.h

    The MigratorSource class models something from which
    Archiveopteryx can migrate messages. Each particular server or
    mailbox format provides a subclass.

    The only function is nextMailbox(), which returns a pointer to
    each mailbox within the MigratorSource in turn, and then a null
    pointer.
*/


/*! Constructs a MigratorSource or some kind. Subclasses must do a
    meaningful job.
*/

MigratorSource::MigratorSource()
{
}


/*! Necessary only to satisfy g++, which wants virtual destructors. */

MigratorSource::~MigratorSource()
{
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

MigratorMailbox::MigratorMailbox( const EString & partialName )
    : n( partialName )
{
}


/*! Necessary only to satisfy g++, which wants virtual
    constructors.
*/

MigratorMailbox::~MigratorMailbox()
{
}


/*! Returns the partial name of this mailbox, ie. the name of the
    source mailbox relative to the MigratorSource's top-level name.

    This is typically a file name including all directories that are
    within the directory being migrated.
*/

EString MigratorMailbox::partialName()
{
    return n;
}


static uint uniq = 0;
static EString * errdir = 0;


/*! \class MigratorMessage migrator.h

    The MigratorMessage provides a message and a source. It's used by
    Migrator and MigratorMailbox to generate and inject messages.

    All parsing is done during construction, so valid() and error()
    returns their final result as soon as the object has been
    constructed.
*/


/*! Constructs a MigratorMessage for \a rfc822, whose source is
    human-readably described by \a desc.
*/

MigratorMessage::MigratorMessage( const EString & rfc822, const EString & desc )
    : s( desc ), o( rfc822 ), m( 0 )
{
    m = new Injectee;
    m->parse( o );
    if ( m->error().isEmpty() )
        return;

    if ( Migrator::verbosity() > 0 )
        fprintf( stdout, "Message %s: Working around error: %s\n",
                 desc.cstr(), m->error().cstr() );
    if ( Migrator::errorCopies() ) {
        EString a = o.anonymised();
        Message * am = new Message;
        am->parse( a );
        EString dir;
        EString name;
        EString c;
        if ( !errdir ) {
            errdir = new EString;
            Allocator::addEternal( errdir, "error directory" );
            errdir->append( "errors/" );
            errdir->appendNumber( getpid() );
            ::mkdir( "errors", 0777 );
            ::mkdir( errdir->cstr(), 0777 );
            if ( Migrator::verbosity() > 0 )
                fprintf( stdout, " - storing error files in %s\n",
                         errdir->cstr() );
        }
        if ( Migrator::verbosity() < 3 &&
             am->error().anonymised() == m->error().anonymised() ) {
            dir = *errdir + "/anonymised";
            name = fn( ++uniq );
            c = a;
        }
        else {
            if ( Migrator::verbosity() > 1 )
                fprintf( stdout, " - Must store as plaintext\n" );
            dir = *errdir + "/plaintext";
            name = fn( ++uniq );
            c = o;
        }
        ::mkdir( dir.cstr(), 0777 );
        File f( dir + "/" + name, File::Write );
        f.write( c );
        if ( Migrator::verbosity() > 1 )
            fprintf( stdout, " - Wrote to %s\n", f.name().cstr() );
    }
    m = Injectee::wrapUnparsableMessage( o, m->error(),
                                         "Unparsable message" );
}


MigratorMessage::~MigratorMessage()
{
}


/*! Returns a description of the message's source, as set using the
    constructor.
*/

EString MigratorMessage::description() const
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

EString MigratorMessage::original() const
{
    return o;
}


/*! Returns the parsed/corrected/inferred Message generated from original(). */

Injectee * MigratorMessage::message()
{
    return m;
}


class MailboxMigratorData
    : public Garbage
{
public:
    MailboxMigratorData()
        : source( 0 ), destination( 0 ),
          migrator( 0 ),
          validated( false ), valid( false ),
          injector( 0 ),
          migrated( 0 ), migrating( 0 )
    {}

    MigratorMailbox * source;
    Mailbox * destination;
    Migrator * migrator;
    List<MigratorMessage> messages;
    bool validated;
    bool valid;
    Injector * injector;
    uint migrated;
    uint migrating;
    EString error;
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
}


/*! Returns true if this migrator's source contains at least one
    message. Whether the message is syntactically valid is irrelevant.
*/

bool MailboxMigrator::valid() const
{
    if ( !d->validated ) {
        d->validated = true;
        Scope x( &d->log );
        MigratorMessage * m = d->source->nextMessage();
        if ( m )
            d->valid = true;
        if ( d->valid ) {
            log( "Source apparently is a valid mailbox" );
            d->messages.append( m );
        }
        else {
            log( "Source is not a valid mailbox" );
        }
    }

    return d->valid;
}


void MailboxMigrator::execute()
{
    if ( d->injector && !d->injector->done() )
        return;

    Scope x( &d->log );

    if ( d->injector && d->injector->failed() ) {
        d->error = "Database error: " + d->injector->error();
        d->migrator->execute();
        return;
    }
    else if ( d->injector ) {
        d->migrated += d->migrating;
        d->migrating = 0;
        d->injector = 0;
    }
    else if ( !d->destination ) {
        UString tmp = d->migrator->destination();
        if ( !d->source->partialName().isEmpty() ) {
            if ( !d->source->partialName().startsWith( "/" ) )
                tmp.append( '/' );
            Utf8Codec u;
            tmp.append( u.toUnicode( d->source->partialName() ) );
        }
        d->destination = Mailbox::obtain( tmp, true );
    }

    uint limit = EventLoop::global()->memoryUsage();
    uint before = Allocator::allocated();
    MigratorMessage * mm = 0;
    do {
        mm = d->source->nextMessage();
        if ( mm )
            d->messages.append( mm );
    } while ( mm && Allocator::allocated() * 2 - before < limit );

    uint done = d->migrator->messagesMigrated();
    if ( done && d->migrator->uptime() ) {
        fprintf( stdout,
                 "Processed %d messages, %.1f/s",
                 done, ((double)done) / d->migrator->uptime() );
        if ( !d->messages.isEmpty() )
            fprintf( stdout, ", next chunk %d messages",
                     d->messages.count() );
        fprintf( stdout, "\n" );
    }

    if ( !d->messages.isEmpty() ) {
        Scope x( new Log );
        log( "Starting migration of " + fn ( d->messages.count() ) +
             " messages starting with " + d->messages.first()->description() );
        List<Injectee> * messages = new List<Injectee>;
        List<MigratorMessage>::Iterator i ( d->messages );
        while ( i ) {
            Injectee * m = i->message();
            m->setFlags( d->destination, i->flags() );
            messages->append( m );
            ++i;
        }
        d->injector = new Injector( this );
        d->injector->addInjection( messages );
        d->injector->execute();
        d->migrating = d->messages.count();
        d->messages.clear();
    }
    else {
        d->migrator->execute();
    }
}


/*! Returns true if this mailbox has processed every message in its
    source to completion, and false if there may be something left to
    do.
*/

bool MailboxMigrator::done() const
{
    if ( !d->validated )
        return false;
    if ( !d->messages.isEmpty() )
        return false;
    return true;
}


/*! Returns the number of messages successfully migrated so far. */

uint MailboxMigrator::migrated() const
{
    return d->migrated;
}


/*! If anything wrong happened, this returns a textual error
    message. If all is in order, this returns an empty string.
*/

EString MailboxMigrator::error() const
{
    return d->error;
}


/*! Returns the number of messages successfully migrated so far. */

uint Migrator::messagesMigrated() const
{
    uint n = d->messagesDone;
    if ( d->working )
        n += d->working->migrated();
    return n;
}


/*! Returns the number of mailboxes completely processed so far. The
    mailbox currently being processed is not counted here.
*/

uint Migrator::mailboxesMigrated() const
{
    return d->mailboxesDone;
}


static uint verbosity = 1;


/*! Records that \a v is the desired verbosity of the Migrator. Higher
    numbers imply more information on stdout/stderr. The initial
    value is 1.
*/

void Migrator::setVerbosity( uint v )
{
    ::verbosity = v;
}


/*! Returns the current verbosity level, as set via setVerbosity(). */

uint Migrator::verbosity()
{
    return ::verbosity;
}


static bool errorCopies = false;


/*! Makes this migrator copy any failing messages if \a copy is true,
    and not copy if \a copy is false. The messages are copied into a
    hardwired directory name, which I haven't decided yet at the time
    of writing.

    The initial value is false;
*/

void Migrator::setErrorCopies( bool copy )
{
    ::errorCopies = copy;
}


/*! Returns the value set by setErrorCopies(). */

bool Migrator::errorCopies()
{
    return ::errorCopies;
}


/*! Returns the list of flags that should be set on the injected
    message. The list may contain duplicates.
*/

const EStringList * MigratorMessage::flags() const
{
    return &f;
}


/*! Records that \a flag should be set on the injected message. */

void MigratorMessage::addFlag( const EString & flag )
{
    f.append( flag );
}


/*! Returns the number of seconds since the Migrator was constructed. */

uint Migrator::uptime()
{
    return (uint)time( 0 ) - d->startup;
}
