#ifndef NOOP_H
#define NOOP_H

#include "command.h"

class Query;
class Transaction;


class Noop
    : public Command
{
public:
    Noop();
    void execute();

private:
    Query *q1, *q2;
    Transaction *t;
};


class Check
    : public Command
{
public:
    void execute();
};


#endif
