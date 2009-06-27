// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LOGSERVER_H
#define LOGSERVER_H

#include "connection.h"
#include "estring.h"
#include "log.h"


class LogServer : public Connection {
public:
    LogServer(int s);
    LogServer();

    void react(Event e);

    void processLine( const EString & );

    static void setLogFile( const EString &, const EString & );
    static void setLogLevel( const EString & );

    static void reopen( int );

    static Log::Severity severity( const EString & );

    // only for SelfLogger
    void output( EString, Log::Severity, const EString & );

private:
    void parse();

private:
    class LogServerData *d;
};

#endif
