#ifndef IDLE_H
#define IDLE_H

#include "imapcommand.h"


class Idle
    : public ImapCommand
{
public:
    void execute();
    void read();
};

#endif
