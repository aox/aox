// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SCHEMA_H
#define SCHEMA_H

#include "event.h"


class Query;
class EString;


class Schema
    : public EventHandler
{
public:
    Schema( EventHandler *, bool = false, bool = true );
    Query * result() const;
    void execute();

    EString serverVersion() const;

    static void checkRevision( EventHandler * );

private:
    class SchemaData *d;
    void fail( const EString &, Query * = 0 );
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
    bool stepTo34();
    bool stepTo35();
    bool stepTo36();
    bool stepTo37();
    bool stepTo38();
    bool stepTo39();
    bool stepTo40();
    bool stepTo41();
    bool stepTo42();
    bool stepTo43();
    bool stepTo44();
    bool stepTo45();
    bool stepTo46();
    bool stepTo47();
    bool stepTo48();
    bool stepTo49();
    bool stepTo50();
    bool stepTo51();
    bool stepTo52();
    bool stepTo53();
    bool stepTo54();
    bool stepTo55();
    bool stepTo56();
    bool stepTo57();
    bool stepTo58();
    bool stepTo59();
    bool stepTo60();
    bool stepTo61();
    bool stepTo62();
    bool stepTo63();
    bool stepTo64();
    bool stepTo65();
    bool stepTo66();
    bool stepTo67();
    bool stepTo68();
    bool stepTo69();
    bool stepTo70();
    bool stepTo71();
    bool stepTo72();
    bool stepTo73();
    bool stepTo74();
    bool stepTo75();
    bool stepTo76();
    bool stepTo77();
    bool stepTo78();
    bool stepTo79();
    bool stepTo80();
    bool stepTo81();
    bool stepTo82();
    bool stepTo83();
    bool stepTo84();
    bool stepTo85();
    bool stepTo86();
    bool stepTo87();
    bool stepTo88();

    void describeStep( const EString & );
};


#endif
