// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EVENT_H
#define EVENT_H

#include "log.h"

class Arena;
class String;


class EventHandler {
public:
    EventHandler();

    Arena *arena() const;
    void setArena( Arena * );
    void setLog( Log * );

    virtual void notify();
    virtual void execute() = 0;
    virtual void log( const String &, Log::Severity = Log::Info );

private:
    Arena *a;
    Log *l;
};


#endif
