// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SEARCH_H
#define SEARCH_H

#include "aoxcommand.h"


class Selector * parseSelector( class StringList * );
void dumpSelector( Selector * );


class ShowSearch
    : public AoxCommand
{
public:
    ShowSearch( StringList * );

    void execute();
};


#endif
