// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef STATUS_H
#define STATUS_H

#include "command.h"


class Status
    : public Command
{
public:
    Status();
    Status( Command *, Mailbox * );

    void parse();
    void execute();

private:
    class StatusData * d;
};


#endif
