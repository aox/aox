// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGSERVER_H
#define LOGSERVER_H

#include "connection.h"
#include "string.h"
#include "log.h"


class LogServer : public Connection {
public:
    LogServer(int s);
    LogServer();
    ~LogServer();

    void react(Event e);

    void processLine( const String & );

    static void setLogFile( const String & );
    static void setLogLevel( const String & );

private:
    void parse();
    void commit( String, Log::Facility, Log::Severity );
    void log( String, Log::Facility, Log::Severity, const String & );
    void output( String, Log::Facility, Log::Severity, const String & );

private:
    class LogServerData *d;
};

#endif
