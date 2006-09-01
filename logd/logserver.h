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

    void react(Event e);

    void processLine( const String & );

    static void setLogFile( const String &, const String & );
    static void setLogLevel( const String & );

    static void reopen( int );

    static Log::Severity severity( const String & );
    static Log::Facility facility( const String & );

    // only for SelfLogger
    void output( String, Log::Facility, Log::Severity, const String & );

private:
    void parse();

private:
    class LogServerData *d;
};

#endif
