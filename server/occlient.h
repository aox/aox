#ifndef OCCLIENT_H
#define OCCLIENT_H

#include "connection.h"


class OCClient
    : public Connection
{
public:
    OCClient( int );

    void parse();
    void react( Event );

    static void setup();

private:
    class OCCData *d;
};


#endif
