#ifndef RENAME_H
#define RENAME_H

#include "imapcommand.h"


class Rename
    : public ImapCommand
{
public:
    Rename()
        : m( 0 )
    {}

    void parse();
    void execute();

private:
    String a, b;
    class Mailbox *m;
};

#endif
