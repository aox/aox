// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ID_H
#define ID_H

#include "command.h"


class Id
    : public Command
{
public:
    void parse();
    void execute();
};


#endif
