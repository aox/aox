#ifndef LOGOUT_H
#define LOGOUT_H

#include "imapcommand.h"


class Logout
    : public ImapCommand
{
public:
    void execute();
};


#endif
