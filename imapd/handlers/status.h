#ifndef STATUS_H
#define STATUS_H

#include "command.h"
#include "string.h"


class Status
    : public Command
{
public:
    Status();

    void parse();
    void execute();

private:
    String name;
    bool messages, uidnext, uidvalidity, recent, unseen;
    class Mailbox *m;
    class ImapSession *session;
};


#endif
