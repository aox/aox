// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef RECORDER_H
#define RECORDER_H

#include "connection.h"

#include "endpoint.h"


class RecorderServer
    : public Connection
{
public:
    RecorderServer( int );

    void react( Event );

    static Endpoint endpoint();

private:
    class RecorderData * d;
};


class RecorderClient
    : public Connection
{
public:
    RecorderClient( class RecorderData * );

    void react( Event );

private:
    class RecorderData * d;
};


#endif
