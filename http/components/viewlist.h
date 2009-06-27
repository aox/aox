// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef VIEWLIST_H
#define VIEWLIST_H

#include "pagecomponent.h"


class ViewList
    : public PageComponent
{
public:
    ViewList();

    void execute();

private:
    class ViewListData * d;
};


#endif
