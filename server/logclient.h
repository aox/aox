#ifndef LOGCLIENT_H
#define LOGCLIENT_H

#include "logger.h"

class String;


class LogClient
    : public Logger
{
public:
    static void setup();
    void send( const String & );

private:
    class LogClientHelper * c;
    LogClient();
};


#endif
