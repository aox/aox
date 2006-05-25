// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef PROGRESSREPORTER_H
#define PROGRESSREPORTER_H

#include "event.h"


class ProgressReporter
    : public EventHandler
{
public:
    ProgressReporter( class Migrator *, uint );

    void execute();

private:
    class ProgressReporterData * d;
};

#endif
