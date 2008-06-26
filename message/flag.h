// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FLAG_H
#define FLAG_H

#include "stringlist.h"
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
    : public EventHandler
{
public:
    FlagCreator( const StringList & f, class Transaction * tr,
                 EventHandler * ev );
    void execute();

    bool done() const;

private:
    void selectFlags();
    void processFlags();
    void insertFlags();
    void processInsert();
    void notify();

private:
    class FlagCreatorData * d;
};




#endif
