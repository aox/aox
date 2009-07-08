// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef RENAME_H
#define RENAME_H

#include "command.h"


class Rename
    : public Command
{
public:
    Rename();

    void parse();
    void execute();

private:
    class RenameData * d;
};


#endif
