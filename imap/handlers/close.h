// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef CLOSE_H
#define CLOSE_H

#include "expunge.h"


class Close
    : public Expunge
{
public:
    Close(): Expunge( false ) {}

    void execute();
};


#endif
