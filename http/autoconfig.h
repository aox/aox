// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef AUTOCONFIG_H
#define AUTOCONFIG_H

#include "event.h"


class HTTP;


class Autoconfig
    : public EventHandler
{
public:
    Autoconfig( HTTP * );

    void execute();

private:
    class AutoconfigData * d;
};


#endif
