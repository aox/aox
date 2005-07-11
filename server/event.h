// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EVENT_H
#define EVENT_H

#include "log.h"

class String;


class EventHandler
    : public Garbage
{
public:
    EventHandler();

    void setLog( Log * );
    Log *log() const;

    virtual void execute() = 0;
    virtual void log( const String &, Log::Severity = Log::Info );
    virtual void commit( Log::Severity = Log::Info );

private:
    Log *l;
};


#endif
