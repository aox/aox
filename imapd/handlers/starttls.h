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
