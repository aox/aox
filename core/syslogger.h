// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
