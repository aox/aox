// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ACL_H
#define ACL_H

#include "command.h"


class SetAcl
    : public Command
{
public:
    SetAcl();

    void parse();
    void execute();

private:
    class AclData * d;
};


class DeleteAcl
    : public Command
{
public:
    DeleteAcl();

    void parse();
    void execute();

private:
    class AclData * d;
};

class GetAcl
    : public Command
{
public:
    GetAcl();

    void parse();
    void execute();

private:
    class AclData * d;
};


class ListRights
    : public Command
{
public:
    ListRights();

    void parse();
    void execute();

private:
    class AclData * d;
};


class MyRights
    : public Command
{
public:
    MyRights();

    void parse();
    void execute();

private:
    class AclData * d;
};


#endif
