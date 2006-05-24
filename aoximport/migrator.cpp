// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "migrator.h"

#include "list.h"
#include "scope.h"
#include "mailbox.h"
#include "allocator.h"
#include "transaction.h"
#include "eventloop.h"
#include "injector.h"
#include "dirtree.h"
#include "mbox.h"

#include <stdio.h>


class MigratorData
    : public Garbage
{
public:
    MigratorData()
        : working( 0 ), target( 0 ),
          messagesDone( 0 ), status( 0 )
    {}

    String destination;
    List< MigratorSource > sources;
    List< MailboxMigrator > * working;
    Mailbox * target;

    uint messagesDone;
    int status;
};


/*! \class Migrator migrator.h

    The Migrator class is a list view displaying information about a
    mailbox migration (and managing the migration, too).

    Its API consists of the two functions start() and running(). The
    execute() function does the heavy loading, by ensuring that the
    Migrator always has four MailboxMigrator objects working. (The
    MailboxMigrator objects must call execute() when they're done.)
*/


/*! Constructs a new Migrator. */

Migrator::Migrator()
    : d( new MigratorData )
{
}


/*! Sets this Migrator's destination to a Mailbox named \a s. */

void Migrator::setDestination( const String &s )
{
    d->destination = s;
}


/*! Creates a MigratorSource object from the string \a s, and adds it to
    this Migrator's list of sources.
*/

void Migrator::addSource( const String &s )
{
    d->sources.append( new MboxDirectory( s ) );
}


/*! Returns the target mailbox, as inferred from setDestination(). This
    function is a ghastly, short-term hack.
*/

Mailbox * Migrator::target() const
{
    return d->target;
}


/*! Fills up the quota of working mailboxes, so we're continuously
    migrating four mailboxes.
*/

void Migrator::execute()
{
    if ( !d->target ) {
        d->target = Mailbox::find( d->destination );
        if ( !d->target ) {
            d->status = -1;
            fprintf( stderr, "aoximport: Target mailbox does not exist: %s\n",
                     d->destination.cstr() );
            EventLoop::global()->shutdown();
            return;
        }
    }

    if ( !d->working ) {
        log( "Starting migration" );
        d->working = new List< MailboxMigrator >;
    }

    List< MailboxMigrator >::Iterator it( d->working );
    while ( it ) {
        List< MailboxMigrator >::Iterator mm( it );
        if ( mm->done() ) {
            d->messagesDone += mm->migrated();
            d->working->take( mm );
        }
        ++it;
    }

    if ( d->working->count() < 4 ) {
        List< MigratorSource >::Iterator sources( d->sources );
        while ( sources ) {
            MigratorSource * source = sources;

            MigratorMailbox * m( source->nextMailbox() );
            while ( m && d->working->count() < 4 ) {
                MailboxMigrator * n = new MailboxMigrator( m, this );
                if ( n->valid() ) {
                    d->working->append( n );
                    n->execute();
                }
                m = source->nextMailbox();
            }

            if ( !m && d->working->count() < 4 ) {
                d->sources.take( sources );
                source = 0;
                if ( sources )
                    source = sources;
            }
            else {
                break;
            }
        }
    }

    if ( d->working->isEmpty() && d->sources.isEmpty() ) {
        d->status = 0;
        EventLoop::global()->shutdown();
    }
}


/*! Returns the status code of this Migrator object.
    (Nascent function, nascent documentation.)
    
    Why is this an int instead of an enum?
*/

int Migrator::status() const
{
    return d->status;
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

MigratorMailbox::MigratorMailbox( const String & partialName )
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
}


MigratorMessage::~MigratorMessage()
{
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
        d->message = d->source->nextMessage();
        if ( d->message )
            d->valid = true;
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
        String e( "Database error: " );
        e.append( d->injector->error() );
    }
    else if ( d->injector ) {
        d->migrated++;
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
            d->migrator->execute();
            return;
        }
        if ( !d->mailboxCreator->done() )
            return;
    }
    else if ( !d->destination ) {
        d->destination = d->migrator->target();
        if ( !d->destination ) {
            log( "Unable to migrate " + d->source->partialName() );
            d->message = 0;
            d->migrator->execute();
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
        String e( "Syntax error: " );
        e.append( d->message->error() );
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
        d->migrator->execute();
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
