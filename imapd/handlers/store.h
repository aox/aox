#ifndef STORE_H
#define STORE_H

#include "imapcommand.h"
#include "string.h"
#include "list.h"
#include "set.h"


class Store
    : public ImapCommand
{
public:
    Store( bool u );

    void parse();
    void execute();

private:
    Set s;
    enum { Add, Replace, Remove } op;
    bool silent;
    bool uid;
    List< String > flags;
};

#endif
