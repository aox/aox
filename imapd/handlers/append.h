#ifndef APPEND_H
#define APPEND_H

#include "imapcommand.h"


class Append
    : public ImapCommand {
public:
    Append();

    void parse();
    void execute();

private:
    uint number( uint );

    class AppendData * d;
};


#endif
