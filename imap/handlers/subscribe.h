// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SUBSCRIBE_H
#define SUBSCRIBE_H

#include "command.h"


class Subscribe
    : public Command
{
public:
    Subscribe();

    void parse();
    void execute();

private:
    class Query * q;
    class Mailbox * m;
};


class Unsubscribe
    : public Command
{
public:
    Unsubscribe();

    void parse();
    void execute();

private:
    UString n;
    class Query * q;
};


#endif
