// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SORT_H
#define SORT_H

#include "search.h"


class Sort
    : public Search
{
public:
    Sort( bool u );

    void parse();
    void execute();
    void process();

private:
    class SortData * d;
};


#endif
