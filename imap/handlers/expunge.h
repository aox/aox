// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef EXPUNGE_H
#define EXPUNGE_H

#include "command.h"


class Expunge
    : public Command
{
public:
    Expunge( bool );

    void parse();

    void execute();

private:
    class ExpungeData *d;
};


#endif
