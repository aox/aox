// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LOGCLIENT_H
#define LOGCLIENT_H

#include "logger.h"

class EString;
class Endpoint;


class LogClient
    : public Logger
{
public:
    static void setup( const EString & );

    void send( const EString &, Log::Severity, const EString & );

    EString name() const;

private:
    class LogClientData * d;
    LogClient();
    bool useSyslog;
};


#endif
