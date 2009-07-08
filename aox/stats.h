// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
