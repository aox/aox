#ifndef CREATE_H
#define CREATE_H

#include "imapcommand.h"


class Create
    : public ImapCommand
{
public:
    Create()
        : m( 0 )
    {}

    void parse();
    void execute();

private:
    String name;
    class Mailbox *m;
};


#endif
