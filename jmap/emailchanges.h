// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef EMAILCHANGES_H
#define EMAILCHANGES_H

#include "method.h"


class EmailChanges
    : public JmapMethod
{
public:
    EmailChanges( EventHandler *, class User *, class Json * );

    void execute();

private:
    class EmailChangesData * d;
};


#endif
