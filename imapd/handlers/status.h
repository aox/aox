#ifndef STATUS_H
#define STATUS_H

#include "command.h"
#include "string.h"


class Status
    : public Command
{
public:
    Status()
        : messages( false ), recent( false ), uidnext( false ),
          uidvalidity( false ), unseen( false )
    {}

    void parse();
    void execute();

private:
    String mailbox;
    bool messages, recent, uidnext, uidvalidity, unseen;
};


#endif
