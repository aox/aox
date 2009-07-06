// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DELETE_H
#define DELETE_H

#include "command.h"


class Delete
    : public Command
{
public:
    Delete();

    void parse();
    void execute();

private:
    class DeleteData * d;
};


#endif
