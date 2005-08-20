// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SCHEMA_H
#define SCHEMA_H

#include "event.h"


class Query;


class Schema
    : public EventHandler
{
public:
    Schema( EventHandler *, bool = false );
    Query * result() const;
    void execute();

    static void check( EventHandler * );

private:
    class SchemaData *d;
};


#endif
