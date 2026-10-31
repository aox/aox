// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#ifndef EMAILGET_H
#define EMAILGET_H

#include "method.h"
#include "integerset.h"


class EmailGet
    : public JmapMethod
{
public:
    EmailGet( EventHandler *, class User *, class Json * );

    void execute();

private:
    class Json * email( class Message * );
    class Json * addresses( class Message *, uint );

private:
    class EmailGetData * d;
};


#endif
