// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
