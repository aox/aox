// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
