#include "logger.h"


static Logger *logger = 0;


/*! \class Logger logger.h
    Abstract base class for things that log messages.
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


/*! \fn virtual void send( const String &s ) = 0

    This virtual function logs \a s in a manner decided by the subclass.
*/


/*! Returns a pointer to the global Logger.
*/

Logger *Logger::logger()
{
    return ::logger;
}
