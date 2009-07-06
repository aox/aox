// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef RESETKEY_H
#define RESETKEY_H

#include "command.h"


class ResetKey
    : public Command
{
public:
    ResetKey();

    void parse();
    void execute();

private:
    Mailbox * m;
    class Query *q;
};


#endif
