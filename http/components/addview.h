// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ADDVIEW_H
#define ADDVIEW_H

#include "pagecomponent.h"

class EString;


class AddView
    : public PageComponent
{
public:
    AddView();

    void execute();

private:
    class AddViewData * d;
};


#endif
