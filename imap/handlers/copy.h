// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef COPY_H
#define COPY_H


#include "command.h"


class Copy
    : public Command
{
public:
    Copy( bool );
    void parse();
    void execute();

private:
    class CopyData * d;
};


#endif
