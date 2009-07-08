// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
