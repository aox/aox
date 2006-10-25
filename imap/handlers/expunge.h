// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef EXPUNGE_H
#define EXPUNGE_H

#include "command.h"


class Expunge
    : public Command
{
public:
    Expunge( bool );

    void parse();

    void execute();
    bool expunge( bool );

private:
    class ExpungeData *d;
};


#endif
