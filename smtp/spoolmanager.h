// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SPOOLMANAGER_H
#define SPOOLMANAGER_H

#include "event.h"


class SpoolManager
    : public EventHandler
{
public:
    SpoolManager();

    void execute();

    static void setup();
    static void shutdown();

    void deliverNewMessage();

private:
    class SpoolManagerData * d;
    void reset();
};


#endif
