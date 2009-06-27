// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef UNDELETE_H
#define UNDELETE_H

#include "aoxcommand.h"


class Undelete
    : public AoxCommand
{
public:
    Undelete( EStringList * );
    void execute();

private:
    class UndeleteData * d;
};


#endif
