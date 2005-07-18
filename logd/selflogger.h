// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SELFLOGGER_H
#define SELFLOGGER_H

#include "logger.h"
#include "connection.h"

class String;
class LogServer;


class SelfLogger: public Logger
{
public:
    SelfLogger();
    void send( const String &,
               Log::Facility, Log::Severity,
               const String & );

    void commit( const String &, Log::Severity );

private:
    LogServer * ls;
};


#endif
