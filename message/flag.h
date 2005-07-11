// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FLAG_H
#define FLAG_H

#include "global.h"
#include "list.h"
#include "event.h"
#include "stringlist.h"


class Flag
    : public Garbage
{
public:
    Flag( const String &, uint );

    String name() const;
    uint id() const;

    static Flag * find( const String & );
    static Flag * find( uint );

    static const List<Flag> * flags();
    static void setup();

private:
    class FlagData * d;
};


class FlagFetcher : public EventHandler
{
public:
    FlagFetcher( EventHandler * owner );

    void execute();

private:
    class FlagFetcherData * d;
    friend class Flag;
};


class FlagCreator : public EventHandler
{
public:
    FlagCreator( EventHandler *, const StringList & );

    void execute();

private:
    class FlagCreatorData * d;
    friend class Flag;
};

#endif
