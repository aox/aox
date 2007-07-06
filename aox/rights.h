// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef RIGHTS_H
#define RIGHTS_H

#include "aoxcommand.h"


class ListRights
    : public AoxCommand
{
public:
    ListRights( StringList * );
    void execute();

private:
    class ListRightsData * d;
    String describe( const String & );
};


class SetAcl
    : public AoxCommand
{
public:
    SetAcl( StringList * );
    void execute();

private:
    class SetAclData * d;
};


#endif
