// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RENAME_H
#define RENAME_H

#include "command.h"


class Rename
    : public Command
{
public:
    Rename()
        : m( 0 )
    {}

    void parse();
    void execute();

private:
    String a, b;
    class Mailbox *m;
};


#endif
