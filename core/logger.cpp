// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "logger.h"


static Logger *logger = 0;


/*! \class Logger logger.h
    Abstract base class for things that log messages.

    Log uses this class to send its messages to the log server, and
    different programs provide different subclasses of Logger to
    communicate with the right server in the right way.

    All subclasses must implement the virtual function send(), which
    sends a single line to the log server.
*/



/*! Stores the address of the newly-created Logger for logger().
*/

Logger::Logger()
{
    ::logger = this;
}


/*! This virtual destructor exists only to ensure that logger() doesn't
    return a bad pointer.
*/

Logger::~Logger()
{
    ::logger = 0;
}


/*! \fn void Logger::send( const String &s )

    This virtual function logs \a s in a manner decided by the
    subclass. \a s already has a trailing CRLF.
*/


/*! Returns a pointer to the global Logger.
*/

Logger *Logger::logger()
{
    return ::logger;
}
