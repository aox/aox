// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FLAG_H
#define FLAG_H

#include "stringlist.h"
#include "injector.h"
#include "event.h"


class Query;


class Flag {
public:
    static void setup();

    static void reload( EventHandler * = 0 );
    static void rollback();

    static void add( const String &, uint );

    static String name( uint );
    static uint id( const String & );
};


class FlagCreator
    : public HelperRowCreator
{
public:
    FlagCreator( const StringList &, class Transaction * );

private:
    Query * makeSelect();
    void processSelect( Query * );
    Query * makeCopy();

private:
    class FlagCreatorData * d;
};




#endif
