// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef CHILDWATCHER_H
#define CHILDWATCHER_H

#include "connection.h"


class ChildWatcher
    : public Connection
{
    ChildWatcher( int, int );

    virtual void react( Event );
    
private:
    int pid;
    int late;
};


#endif
