// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
