// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef THREADGET_H
#define THREADGET_H

#include "method.h"
#include "integerset.h"


class ThreadGet
    : public JmapMethod
{
public:
    ThreadGet( EventHandler *, class User *, class Json * );

    void execute();

private:
    class ThreadGetData * d;
};


#endif
