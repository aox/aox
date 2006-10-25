// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef VIEW_H
#define VIEW_H

#include "search.h"


class View
    : public Search
{
public:
    View();

    void parse();
    void execute();

private:
    class ViewData * d;
};


#endif
