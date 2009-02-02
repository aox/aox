// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef UPDATEDB_H
#define UPDATEDB_H

#include "aoxcommand.h"


class UpdateDatabase
    : public AoxCommand
{
public:
    UpdateDatabase( EStringList * );
    void execute();

private:
    class UpdateDatabaseData * d;
    bool convertField( uint, uint, const EString &, uint, uint,
                       const EString & );
};


#endif
