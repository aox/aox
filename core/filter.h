// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef FILTER_H
#define FILTER_H

#include "global.h"


class Buffer;

class Filter {
public:
    Filter();
    virtual ~Filter();

    virtual int read( char *, uint, Buffer * ) = 0;
    virtual int write( char *, uint, Buffer * ) = 0;
    virtual void flush( Buffer * ) {}
};


#endif
