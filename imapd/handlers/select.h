#ifndef SELECT_H
#define SELECT_H

#include "imapcommand.h"


class Select
    : public ImapCommand
{
public:
    Select( bool ro = false )
        : readOnly( ro ), m( 0 )
    {}

    void parse();
    void execute();

private:
    String name;
    bool readOnly;
    class Mailbox *m;
};


class Examine
    : public Select
{
public:
    Examine()
        : Select( true )
    {}
};


#endif
