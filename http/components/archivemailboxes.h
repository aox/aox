// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
