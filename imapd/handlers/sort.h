// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SORT_H
#define SORT_H

#include "command.h"


class Sort
    : public Command
{
public:
    Sort( bool u );

    void parse();
    void execute();

private:
    class SortData * d;
};


#endif
