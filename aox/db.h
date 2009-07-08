// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef DB_H
#define DB_H

#include "aoxcommand.h"


class ShowSchema
    : public AoxCommand
{
public:
    ShowSchema( EStringList * );
    void execute();

private:
    class Query * q;
};


class UpgradeSchema
    : public AoxCommand
{
public:
    UpgradeSchema( EStringList * );
    void execute();

private:
    class Query * q;
};


class Vacuum
    : public AoxCommand
{
public:
    Vacuum( EStringList * );
    void execute();

private:
    class Transaction * t;
    class RetentionSelector * r;
    class Selector * s;
};


class GrantPrivileges
    : public AoxCommand
{
public:
    GrantPrivileges( EStringList * );
    void execute();

private:
    bool commit;
    class Transaction * t;
};


class TuneDatabase
    : public AoxCommand
{
public:
    TuneDatabase( EStringList * );
    void execute();

private:
    class TuneDatabaseData * d;
};


#endif
