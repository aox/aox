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
        Quit, Capa, Noop, Stls, Auth, User, Pass,
        Stat, List, Retr, Dele, Rset, Top,
        Session
    };

    PopCommand( class POP *, Command, class StringList * );

    void read();
    void execute();
    void finish();
    bool done();

private:
    class PopCommandData * d;

    String nextArg();
    bool startTls();
    bool auth();
    bool user();
    bool pass();
    bool session();
    bool fetch822Size();
    bool stat();
    bool list();
    bool retr( bool );
    bool dele();
};


#endif
