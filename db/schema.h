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
    static int currentRevision();

private:
    class SchemaData *d;
    void fail( const String &, Query * = 0 );
    bool singleStep();
    bool stepTo2();
    bool stepTo3();
    bool stepTo4();
    bool stepTo5();
    bool stepTo6();
    bool stepTo7();
    bool stepTo8();
    bool stepTo9();
    bool stepTo10();
    bool stepTo11();
    bool stepTo12();
    bool stepTo13();
    bool stepTo14();
    bool stepTo15();
    bool stepTo16();
    bool stepTo17();
    bool stepTo18();
};


#endif
