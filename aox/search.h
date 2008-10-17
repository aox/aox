// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SEARCH_H
#define SEARCH_H

#include "aoxcommand.h"


void dumpSelector( class Selector * );


class ShowSearch
    : public AoxCommand
{
public:
    ShowSearch( StringList * );

    void execute();
};


#endif
