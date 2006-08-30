// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STDERRLOGGER_H
#define STDERRLOGGER_H

#include "logger.h"


class StderrLogger
    : public Logger
{
public:
    StderrLogger( const String & name, uint verbosity );
    void send( const String &,
               Log::Facility, Log::Severity,
               const String & );
    void commit( const String &, Log::Severity ) {}
    virtual String name() const;
private:
    String n;
    uint v;
};


#endif
