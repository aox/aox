// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef QUEUE_H
#define QUEUE_H

#include "aoxcommand.h"


class ShowQueue
    : public AoxCommand
{
public:
    ShowQueue( EStringList * );
    void execute();

private:
    class Query * q;
    class Query * qr;
};


#endif
