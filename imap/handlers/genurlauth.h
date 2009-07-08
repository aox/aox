// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef GENURLAUTH_H
#define GENURLAUTH_H

#include "command.h"


class GenUrlauth
    : public Command
{
public:
    GenUrlauth();

    void parse();
    void execute();

private:
    class GenUrlauthData *d;
};


#endif
