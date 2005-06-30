// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "cstring.h"

#include "migrator.h"


/*!  Constructs an empty

*/

Migrator::Migrator( QWidget * parent )
    : QWidget( parent )
{
    
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


/*! Constructs a mailbox from which MigratorMessage objects can be
    fetched. Subclasses must do this properly.
*/

MigratorMailbox::MigratorMailbox()
{
    // nothing
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
    source = source; // XXX
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
