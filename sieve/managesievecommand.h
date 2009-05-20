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
        PutScript, ListScripts, SetActive, GetScript, DeleteScript,
        XAoxExplain,
        Unknown
    };

    ManageSieveCommand( class ManageSieve *, Command );
    void setArguments( const EString & );

    void execute();
    bool done();

private:
    class ManageSieveCommandData * d;

    bool startTls();
    bool authenticate();
    bool haveSpace();
    bool putScript();
    bool listScripts();
    bool setActive();
    bool getScript();
    bool deleteScript();
    bool renameScript();
    bool explain();

    EString string();
    uint number();
    void whitespace();
    void end();

    void no( const EString & );

    static EString encoded( const EString & );
};


#endif
