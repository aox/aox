#ifndef LOGSERVER_H
#define LOGSERVER_H

#include "connection.h"
#include "string.h"
#include "log.h"


class LogServer : public Connection {
public:
    LogServer(int s);

    void react(Event e);

private:
    void parse();
    void process( String, String, String );
    void commit( uint, Log::Severity );
    void log( uint, Log::Severity, const String & );
    void output( uint, Log::Severity, const String & );

private:
    class LogServerData *d;
};

#endif
