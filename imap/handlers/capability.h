// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CAPABILITY_H
#define CAPABILITY_H

#include "command.h"


class Capability
    : public Command
{
public:
    void execute();

    static EString capabilities( IMAP *, bool = false );
};


#endif
