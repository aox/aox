// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RIGHTS_H
#define RIGHTS_H

#include "aoxcommand.h"


class ListRights
    : public AoxCommand
{
public:
    ListRights( EStringList * );
    void execute();

private:
    class ListRightsData * d;
    EString describe( const EString & );
};


class SetAcl
    : public AoxCommand
{
public:
    SetAcl( EStringList * );
    void execute();

private:
    class SetAclData * d;
};


#endif
