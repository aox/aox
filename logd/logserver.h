#ifndef LOGSERVER_H
#define LOGSERVER_H

#include "connection.h"
#include "string.h"
#include "log.h"


class LogServer : public Connection {
public:
    LogServer(int s);

    void react(Event e);

    void processLine( const String & );

private:
    void parse();
    void process( String, String, String );
    void commit( String, Log::Facility, Log::Severity );
    void log( String, Log::Facility, Log::Severity, const String & );
    void output( String, Log::Facility, Log::Severity, const String & );

private:
    class LogServerData *d;
};

#endif
