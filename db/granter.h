// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef GRANTER_H
#define GRANTER_H

#include "event.h"


class Granter
    : public EventHandler
{
public:
    Granter( const String &, class Transaction * );

    void execute();

private:
    class GranterData * d;
};


#endif
