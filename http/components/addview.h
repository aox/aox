// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
