// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HELP_H
#define HELP_H

#include "aoxcommand.h"


class Help
    : public AoxCommand
{
public:
    Help( StringList * );
    void execute();
};


#endif
