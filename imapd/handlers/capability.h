#ifndef CAPABILITY_H
#define CAPABILITY_H

#include "imapcommand.h"


class Capability
    : public ImapCommand
{
public:
    void execute();

    static const char * capabilities();
};

#endif
