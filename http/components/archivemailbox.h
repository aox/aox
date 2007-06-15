// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ARCHIVEMAILBOX_H
#define ARCHIVEMAILBOX_H

#include "pagecomponent.h"


class MessageSet;


class ArchiveMailbox
    : public PageComponent
{
public:
    ArchiveMailbox( class Link * );

    void execute();
    
private:
    String timespan( const MessageSet & ) const;

private:
    class ArchiveMailboxData * d;
};


#endif
