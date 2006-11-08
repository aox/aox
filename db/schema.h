// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SCHEMA_H
#define SCHEMA_H

#include "event.h"


class Query;
class String;


class Schema
    : public EventHandler
{
public:
    Schema( EventHandler *, bool = false, bool = true );
    Query * result() const;
    void execute();

    String serverVersion() const;

    static void checkRevision( EventHandler * );

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
    bool stepTo19();
    bool stepTo20();
    bool stepTo21();
    bool stepTo22();
    bool stepTo23();
    bool stepTo24();
    bool stepTo25();
    bool stepTo26();
    bool stepTo27();
    bool stepTo28();
    bool stepTo29();
    bool stepTo30();
    bool stepTo31();
    bool stepTo32();
    bool stepTo33();

    void describeStep( const String & );
};


#endif
