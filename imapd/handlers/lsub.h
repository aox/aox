// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LSUB_H
#define LSUB_H

#include "command.h"
#include "string.h"


class Lsub
    : public Command
{
public:
    Lsub();

    void parse();
    void execute();

private:
    bool match( const String &, const String & );

    class Query *q;
    String ref;
    String pat;
};


#endif
