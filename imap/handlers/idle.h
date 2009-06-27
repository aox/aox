// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef IDLE_H
#define IDLE_H

#include "command.h"


class Idle
    : public Command
{
public:
    Idle(): idling( false ) {}

    void execute();
    void read();

private:
    bool idling;
};


#endif
