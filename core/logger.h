// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LOGGER_H
#define LOGGER_H

class String;

#include "global.h"
#include "log.h"


class Logger
    : public Garbage
{
public:
    Logger();
    virtual ~Logger();

    virtual void send( const String &,
                       Log::Facility, Log::Severity,
                       const String & ) = 0;

    virtual String name() const;

    static Logger *global();
};


#endif
