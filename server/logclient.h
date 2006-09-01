// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGCLIENT_H
#define LOGCLIENT_H

#include "logger.h"

class String;
class Endpoint;


class LogClient
    : public Logger
{
public:
    static void setup( const String & );

    void send( const String &,
               Log::Facility, Log::Severity,
               const String & );

    String name() const;

private:
    class LogClientData * d;
    LogClient();
};


#endif
