// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef OBLITERATE_H
#define OBLITERATE_H

#include "command.h"


class XObliterate
    : public Command
{
public:
    XObliterate(): t( 0 ) {}

    void parse();
    void execute();

private:
    String n;
    class Query * a;
    class Transaction * t;
};


#endif
