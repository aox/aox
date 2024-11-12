// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ENABLE_H
#define ENABLE_H

#include "command.h"


class Enable
    : public Command
{
public:
    Enable();

    void parse();
    void execute();

private:
    bool condstore;
    bool annotate;
    bool utf8;
    bool qresync;
    bool uidonly;
};


#endif
