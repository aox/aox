// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LSUB_H
#define LSUB_H

#include "listext.h"
#include "string.h"


class Lsub
    : public Listext
{
public:
    Lsub();

    void parse();
    void execute();

private:
    class Query *q;
    class Mailbox * ref;
    String pat;
};


#endif
