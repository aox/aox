// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef CACHELOOKUP_H
#define CACHELOOKUP_H

#include "global.h"


class CacheLookup
    : public Garbage
{
public:
    CacheLookup();

    enum State { Executing, Completed };
    void setState( State );
    State state() const;
    bool done() const;

private:
    State st;
};


#endif
