#ifndef EXPUNGE_H
#define EXPUNGE_H

#include "imapcommand.h"


class Expunge
    : public ImapCommand
{
public:
    void execute();
    void expunge( bool );
};


#endif
