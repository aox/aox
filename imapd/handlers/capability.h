#ifndef CAPABILITY_H
#define CAPABILITY_H

#include "command.h"


class Capability
    : public Command
{
public:
    void execute();

    static String capabilities( IMAP * );

    static void setup();
};


#endif
