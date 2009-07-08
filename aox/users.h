// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef USERS_H
#define USERS_H

#include "aoxcommand.h"


class ListUsers
    : public AoxCommand
{
public:
    ListUsers( EStringList * );
    void execute();

private:
    class Query * q;
};


class CreateUser
    : public AoxCommand
{
public:
    CreateUser( EStringList * );
    void execute();

private:
    class CreateUserData * d;
};


class DeleteUser
    : public AoxCommand
{
public:
    DeleteUser( EStringList * );
    void execute();

private:
    class DeleteUserData * d;
};


class ChangePassword
    : public AoxCommand
{
public:
    ChangePassword( EStringList * );
    void execute();

private:
    class Query * q;
};


class ChangeUsername
    : public AoxCommand
{
public:
    ChangeUsername( EStringList * );
    void execute();

private:
    class ChangeUsernameData * d;
};


class ChangeAddress
    : public AoxCommand
{
public:
    ChangeAddress( EStringList * );
    void execute();

private:
    class ChangeAddressData * d;
};


#endif
