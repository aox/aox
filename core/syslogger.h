#ifndef SYSLOGGER_H
#define SYSLOGGER_H

#include "logger.h"

class String;


class Syslogger: public Logger
{
public:
    Syslogger( const char * );

    void send( const String & );
};


#endif
