// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ANONYMISE_H
#define ANONYMISE_H

#include "aoxcommand.h"


class Anonymise
    : public AoxCommand
{
public:
    Anonymise( EStringList * );
    void execute();
};


#endif
