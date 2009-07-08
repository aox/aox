// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef VIEWS_H
#define VIEWS_H

#include "aoxcommand.h"


class CreateView
    : public AoxCommand
{
public:
    CreateView( EStringList * );
    void execute();

private:
    class CreateViewData * d;
};


#endif
