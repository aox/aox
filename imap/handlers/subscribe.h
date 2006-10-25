// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SUBSCRIBE_H
#define SUBSCRIBE_H

#include "command.h"


class Subscribe
    : public Command
{
public:
    enum Mode { Add, Remove };

    Subscribe( Mode = Add );

    void parse();
    void execute();

private:
    Mode mode;
    String name;
    bool selected;
    class Query *q;
    class Mailbox *m;
};


class Unsubscribe
    : public Subscribe
{
public:
    Unsubscribe();
};


#endif
