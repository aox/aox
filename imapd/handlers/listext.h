#ifndef LISTEXT_H
#define LISTEXT_H

#include "command.h"


// this file is misnamed. the only way out seems to be calling the
// handlers something longer, e.g. ImapCList for this class. but let's
// delay that until we have more than one problem.


class Listext
    : public Command
{
public:
    Listext();

    void parse();
    void execute();

private:
    String listMailbox();

private:
    class ListextData * d;
};


#endif
