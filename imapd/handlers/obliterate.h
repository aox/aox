// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OBLITERATE_H
#define OBLITERATE_H

#include "command.h"


class XObliterate
    : public Command
{
public:
    XObliterate(): t( 0 ) {}
    void execute();

    class Transaction * t;
    class Query * a;
};


#endif
