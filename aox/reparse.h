// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef REPARSE_H
#define REPARSE_H

#include "aoxcommand.h"


class Reparse
    : public AoxCommand
{
public:
    Reparse( StringList * );
    void execute();

    String writeErrorCopy( const String & );

private:
    class ReparseData * d;
};


#endif
