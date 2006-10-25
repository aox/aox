// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STATUS_H
#define STATUS_H

#include "command.h"


class Status
    : public Command
{
public:
    Status();

    void parse();
    void execute();

private:
    class StatusData * d;
};


#endif
