// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
