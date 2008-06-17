// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FLAG_H
#define FLAG_H

#include "stringlist.h"

class EventHandler;
class Query;


class Flag {
public:
    static void setup();

    static void reload( EventHandler * = 0 );
    static void rollback();

    static Query * create( const StringList &, class Transaction *,
                           EventHandler * );

    static void add( const String &, uint );

    static String name( uint );
    static uint id( const String & );
};


#endif
