// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef MANAGESIEVECOMMAND_H
#define MANAGESIEVECOMMAND_H

#include "event.h"
#include "managesieve.h"


class ManageSieveCommand
    : public EventHandler
{
public:
    enum Command {
        Authenticate, StartTls, Logout, Capability, HaveSpace,
        PutScript, ListScripts, SetActive, GetScript, DeleteScript
    };

    ManageSieveCommand( class ManageSieve *, Command, class StringList * );

    void read();
    void execute();
    void finish();
    bool done();

private:
    class ManageSieveCommandData * d;

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
