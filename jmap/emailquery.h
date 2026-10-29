// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef EMAILQUERY_H
#define EMAILQUERY_H

#include "method.h"


class Selector;


class EmailQuery
    : public JmapMethod
{
public:
    EmailQuery( EventHandler *, class User *, class Json * );

    void execute();

private:
    Selector * condition( class Json *, EString & );
    EString order( class Json *, EString & );

private:
    class EmailQueryData * d;
};


#endif
