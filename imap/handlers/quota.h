// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef QUOTA_H
#define QUOTA_H

#include "command.h"


class GetQuota
    : public Command
{
public:
    GetQuota(): Command(), q( 0 ) {}

    void parse();
    void execute();

private:
    class Query * q;
};


class SetQuota
    : public Command
{
public:
    void parse();
    void execute();
};


class GetQuotaRoot
    : public GetQuota
{
public:
    GetQuotaRoot(): GetQuota(), m( 0 ), x( false ) {}

    void parse();
    void execute();

private:
    class Mailbox * m;
    bool x;
};


class SetQuotaRoot
    : public Command
{
public:
    void parse();
    void execute();
};




#endif
