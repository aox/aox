// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EGD_H
#define EGD_H

#include "connection.h"


class EntropyProvider
    : public Connection
{
public:
    EntropyProvider( int );

    void react( Event );

private:
    void process();
};


#endif
