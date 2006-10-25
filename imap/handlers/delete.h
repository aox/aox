// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DELETE_H
#define DELETE_H

#include "command.h"


class Delete
    : public Command
{
public:
    Delete();

    void parse();
    void execute();

private:
    class DeleteData * d;
};


#endif
