#ifndef LOGCLIENT_H
#define LOGCLIENT_H

#include "logger.h"
#include "connection.h"

class String;


class LogClient
    : public Logger
{
private:
    LogClient();

public:
    void send( const String & );

    static void setup();

private:
    class LogClientHelper * c;
};


class LogClientHelper: public Connection
{
private:
    friend LogClient;
    LogClientHelper( int fd ): Connection( fd ) {}

    void react( Event );
};


#endif
