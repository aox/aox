// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ARCHIVEMAILBOXES_H
#define ARCHIVEMAILBOXES_H

#include "pagecomponent.h"


class ArchiveMailboxes
    : public PageComponent
{
public:
    ArchiveMailboxes();

    void execute();

private:
    class ArchiveMailboxesData * d;
};


#endif
