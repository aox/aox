// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STATS_H
#define STATS_H

#include "aoxcommand.h"


class ShowCounts
    : public AoxCommand
{
public:
    ShowCounts( EStringList * );
    void execute();

private:
    class ShowCountsData * d;
};


#endif
