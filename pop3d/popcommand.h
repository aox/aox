// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef POPCOMMAND_H
#define POPCOMMAND_H

#include "event.h"
#include "pop.h"


class PopCommand
    : public EventHandler
{
public:
    enum Command {
        Quit, Capa, Noop, User, Pass
    };

    PopCommand( class POP *, Command, class StringList * );

    void execute();
    void finish();
    bool done();

private:
    class PopCommandData * d;

    String nextArg();
    bool pass();
};


#endif
