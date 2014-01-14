// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef FLAG_H
#define FLAG_H

#include "estringlist.h"
#include "event.h"


class Query;


class Flag
    : public EventHandler
{
private:
    Flag();

public:
    static void setup();

    static EString name( uint );
    static uint id( const EString & );

    static bool isSeen( uint );
    static bool isDeleted( uint );

    static uint largestId();
    static EStringList allFlags();

    void execute();


private:
    friend class FlagObliterator;
    class FlagData * d;
};


#endif
