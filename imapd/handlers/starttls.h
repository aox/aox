// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STARTTLS_H
#define STARTTLS_H

#include "command.h"


class StartTLS
    : public Command
{
public:
    StartTLS();

    void parse();
    void execute();

private:
    class TlsServer * tlsServer;
};


#endif
