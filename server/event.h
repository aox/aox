// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef EVENT_H
#define EVENT_H

#include "log.h"

class EString;


class EventHandler
    : public Garbage
{
public:
    EventHandler();
    virtual ~EventHandler();

    void setLog( Log * );
    Log *log() const;

    void notify();
    virtual void execute() = 0;
    virtual void log( const EString &, Log::Severity = Log::Info ) const;

private:
    Log *l;
};


#endif
