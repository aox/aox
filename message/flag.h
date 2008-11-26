// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FLAG_H
#define FLAG_H

#include "stringlist.h"
#include "event.h"


class Query;


class Flag
    : public EventHandler
{
private:
    Flag();

public:
    static void setup();

    static String name( uint );
    static uint id( const String & );
    static uint largestId();

    static StringList allFlags();

    void execute();

private:
    friend class FlagObliterator;
    class FlagData * d;
};


#endif
