// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef URLFETCH_H
#define URLFETCH_H

#include "command.h"


class UrlFetch
    : public Command
{
public:
    UrlFetch();

    void parse();
    void execute();

private:
    class UrlFetchData *d;
};


#endif
