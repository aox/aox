#ifndef UNSELECT_H
#define UNSELECT_H

#include "imapcommand.h"


class Unselect
    : public ImapCommand
{
public:
    void execute();
};


#endif
