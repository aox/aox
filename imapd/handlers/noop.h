#ifndef NOOP_H
#define NOOP_H

#include "imapcommand.h"


class Noop
    : public ImapCommand
{
public:
    void execute();
};


class Check
    : public ImapCommand
{
public:
    void execute();
};


#endif
