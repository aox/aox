// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef EGD_H
#define EGD_H

#include "connection.h"


class EntropyProvider
    : public Connection
{
public:
    EntropyProvider( int );

    void react( Event );

private:
    void process();
};


#endif
