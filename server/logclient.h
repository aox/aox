#ifndef LOGCLIENT_H
#define LOGCLIENT_H

#include "logger.h"
#include "connection.h"

class String;


class LogClient
    : public Logger, public Connection
{
private:
    LogClient( int );

public:
    void send( const String & );
    void react( Event );

    static void setup();
};


#endif
