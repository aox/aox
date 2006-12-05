// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
