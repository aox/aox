// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef GRANTER_H
#define GRANTER_H

#include "event.h"


class Granter
    : public EventHandler
{
public:
    Granter( const EString &, class Transaction * );

    void execute();

private:
    class GranterData * d;
};


#endif
