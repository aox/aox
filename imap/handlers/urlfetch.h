// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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
