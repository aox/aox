#ifndef NOOP_H
#define NOOP_H

#include "command.h"


class Noop
    : public Command
{
public:
    Noop() : st( Started ) {}

    void execute();

private:
    enum { Started, Waiting } st;
    class Query *q;
    int n;
};

#endif
