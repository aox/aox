#ifndef FLAG_H
#define FLAG_H

#include "global.h"
#include "list.h"
#include "event.h"

class String;


class Flag
{
public:
    Flag( const String &, uint );

    String name() const;
    uint id() const;

    static Flag * flag( const String & );
    static Flag * flag( uint );

    static const List<Flag> * flags();
    static void setup();

private:
    class FlagData * d;
};


class FlagFetcher : public EventHandler
{
public:
    FlagFetcher();

    void execute();

private:
    class FlagFetcherData * d;
    friend class Flag;
};

#endif
