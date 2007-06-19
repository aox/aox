// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SPOOLMANAGER_H
#define SPOOLMANAGER_H

#include "event.h"


class SpoolManager
    : public EventHandler
{
public:
    SpoolManager();

    void execute();

    static void run();
    static void setup();
    static void shutdown();

private:
    class SpoolManagerData * d;
};


#endif
