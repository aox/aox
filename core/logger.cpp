// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logger.h"

#include "string.h"
#include "allocator.h"


static Logger *logger = 0;


/*! \class Logger logger.h
    Abstract base class for things that log messages.

    All subclasses of Logger must implement the send() virtual function,
    and take responsibility for correctly logging the lines of text that
    are passed to it.

    A program creates one instance of a Logger subclass at startup and
    uses Logger::global() to process any messages sent to a Log object
    thereafter.
*/

/*! Stores the address of the newly-created Logger for global(). */

Logger::Logger()
{
    ::logger = this;
    Allocator::addEternal( this, "logger" );
}


/*! \fn void Logger::send( const String &id,
                           Log::Facility f, Log::Severity s,
                           const String & m )

    This virtual function logs the message \a m belonging to
    transaction \a id, whose severity is \a s and which is logged by
    \a f, in a manner decided by the subclass.

    \a id uniquely identifies a Log object.
*/


/*! \fn void Logger::commit( const String &id, Log::Severity s )

    This virtual function instructs the logger to commit all messages
    for \a id with severity \a s or higher. Messages with lower
    severity may be logged or discarded at the logger's discretion.

    The default implementation is a no-op.
*/

void Logger::commit( const String &, Log::Severity )
{
}


/*! This virtual destructor exists only to ensure that global() doesn't
    return a bad pointer.
*/

Logger::~Logger()
{
    ::logger = 0;
}


/*! Returns a pointer to the global Logger. */

Logger *Logger::global()
{
    return ::logger;
}


/*! Returns an application name. Subclasses must provide this name.

    I don't like this mechanism. It's hacky. Only exists to let Log
    (in core) get at information held by the Server class (in server).
*/

String Logger::name() const
{
    return "Mailstore";
}
