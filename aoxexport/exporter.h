// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EXPORTER_H
#define EXPORTER_H

#include "event.h"

class Selector;
class UString;


class Exporter
    : public EventHandler
{
public:
    Exporter( const UString &, Selector * );

    void execute();

private:
    class ExporterData * d;
};

#endif
