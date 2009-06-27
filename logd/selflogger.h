// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
