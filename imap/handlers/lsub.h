// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LSUB_H
#define LSUB_H

#include "listext.h"


class Lsub
    : public Listext
{
public:
    Lsub();

    void parse();
    void execute();

private:
    void reference();

private:
    class LsubData * d;
};


#endif
