// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SELFLOGGER_H
#define SELFLOGGER_H

#include "logger.h"
#include "connection.h"

class EString;
class LogServer;


class SelfLogger: public Logger
{
public:
    SelfLogger();

    void send( const EString &, Log::Severity, const EString & );

private:
    LogServer * ls;
};


#endif
