// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SCHEMACHECKER_H
#define SCHEMACHECKER_H

#include "event.h"


class SchemaChecker
    : public EventHandler
{
public:
    SchemaChecker( class Transaction * );

    void execute();

    void enqueue();
    void checkColumns();

private:
    class SchemaCheckerData * d;
};

#endif
