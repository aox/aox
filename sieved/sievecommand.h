// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SIEVECOMMAND_H
#define SIEVECOMMAND_H

#include "event.h"
#include "sieve.h"


class SieveCommand
    : public EventHandler
{
public:
    enum Command {
        Authenticate, StartTls, Logout, Capability, HaveSpace,
        PutScript, ListScripts, SetActive, GetScript, DeleteScript
    };

    SieveCommand( class Sieve *, Command, class StringList * );

    void read();
    void execute();
    void finish();
    bool done();

private:
    class SieveCommandData * d;

    String nextArg();
    bool startTls();
    bool authenticate();
    bool haveSpace();
    bool putScript();
    bool listScripts();
    bool setActive();
    bool getScript();
    bool deleteScript();
};


#endif
