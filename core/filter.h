// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
