// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef APPEND_H
#define APPEND_H

#include "command.h"


class Append
    : public Command
{
public:
    Append();

    void parse();
    void execute();

private:
    class AppendData * d;
};


#endif
