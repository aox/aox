#ifndef STORE_H
#define STORE_H

#include "command.h"
#include "string.h"
#include "list.h"
#include "messageset.h"


class Store
    : public Command
{
public:
    Store( bool u );

    void parse();
    void execute();

private:
    MessageSet s;
    enum { Add, Replace, Remove } op;
    bool silent;
    bool uid;
    List< String > flags;
};


#endif
