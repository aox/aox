// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef REPARSE_H
#define REPARSE_H

#include "aoxcommand.h"


class Reparse
    : public AoxCommand
{
public:
    Reparse( EStringList * );
    void execute();

    EString writeErrorCopy( const EString & );

private:
    class ReparseData * d;
};


#endif
