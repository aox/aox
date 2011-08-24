// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef STARTTLS_H
#define STARTTLS_H

#include "command.h"


class StartTLS
    : public Command
{
public:
    StartTLS();

    void parse();
    void execute();

    void emitResponses();
};


#endif
