// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ALIASES_H
#define ALIASES_H

#include "aoxcommand.h"


class ListAliases
    : public AoxCommand
{
public:
    ListAliases( EStringList * );
    void execute();

private:
    class Query * q;
};


class CreateAlias
    : public AoxCommand
{
public:
    CreateAlias( EStringList * );
    void execute();

private:
    class CreateAliasData * d;
};


class DeleteAlias
    : public AoxCommand
{
public:
    DeleteAlias( EStringList * );
    void execute();

private:
    class Query * q;
};


#endif
