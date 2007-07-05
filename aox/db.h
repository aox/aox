// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef DB_H
#define DB_H

#include "aoxcommand.h"


class ShowSchema
    : public AoxCommand
{
public:
    ShowSchema( StringList * );
    void execute();

private:
    class Query * q;
};


class UpgradeSchema
    : public AoxCommand
{
public:
    UpgradeSchema( StringList * );
    void execute();

private:
    class Query * q;
};


class Vacuum
    : public AoxCommand
{
public:
    Vacuum( StringList * );
    void execute();

private:
    class Transaction * t;
};


#endif
