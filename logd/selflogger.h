#ifndef SELFLOGGER_H
#define SELFLOGGER_H

#include "logger.h"
#include "connection.h"

class String;
class LogServer;


class SelfLogger: public Logger
{
public:
    SelfLogger();
    void send( const String & );

private:
    LogServer * ls;
};


#endif
