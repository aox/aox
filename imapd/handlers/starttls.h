#ifndef STARTTLS_H
#define STARTTLS_H

#include "imapcommand.h"


class StartTLS
    : public ImapCommand
{
public:
    void execute();
};


#endif
