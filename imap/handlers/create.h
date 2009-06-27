// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CREATE_H
#define CREATE_H

#include "command.h"


class Create
    : public Command
{
public:
    Create();

    void parse();
    void execute();

private:
    class CreateData * d;
};


#endif
