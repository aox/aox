#ifndef ID_H
#define ID_H

#include "imapcommand.h"


class Id
    : public ImapCommand
{
public:
    void parse();
    void execute();
};


#endif
