// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef UNDELETE_H
#define UNDELETE_H

#include "aoxcommand.h"


class Undelete
    : public AoxCommand
{
public:
    Undelete( EStringList * );
    void execute();

private:
    class UndeleteData * d;
};


#endif
