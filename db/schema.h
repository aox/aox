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
    void fail( const String &, Query * = 0 );
    bool singleStep();
    bool step1();
    bool step2();
    bool step3();
    bool step4();
    bool step5();
    bool step6();
    bool step7();
    bool step8();
    bool step9();
    bool step10();
    bool step11();
    bool step12();
};


#endif
