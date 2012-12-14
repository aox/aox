// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef BEEPER_H
#define BEEPER_H

#include "connection.h"


class Beeper
    : public Connection
{
    Beeper( int );

    virtual void react( Event );
};


#endif
