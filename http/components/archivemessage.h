// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ARCHIVEMESSAGE_H
#define ARCHIVEMESSAGE_H

#include "pagecomponent.h"


class ArchiveMessage
    : public PageComponent
{
public:
    ArchiveMessage( class Link * );

    void execute();

private:
    class ArchiveMessageData * d;
};


#endif
