// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef HELP_H
#define HELP_H

#include "aoxcommand.h"


class Help
    : public AoxCommand
{
public:
    Help( EStringList * );
    void execute();
};


#endif
