// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ARCHIVETHREAD_H
#define ARCHIVETHREAD_H

#include "pagecomponent.h"


class ArchiveThread
    : public PageComponent
{
public:
    ArchiveThread( class Link * );

    void execute();

private:
    class ArchiveThreadData * d;
};


#endif
