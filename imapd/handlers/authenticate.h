// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "command.h"
#include "string.h"


class Authenticate
    : public Command
{
public:
    Authenticate();

    void parse();
    void execute();
    void read();

private:
    class SaslMechanism *m;
    String *r;
    String t;
};


#endif
