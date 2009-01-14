// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef ARCHIVEMAILBOX_H
#define ARCHIVEMAILBOX_H

#include "pagecomponent.h"


class IntegerSet;


class ArchiveMailbox
    : public PageComponent
{
public:
    ArchiveMailbox( class Link * );

    void execute();

private:
    String threadRendering( class SubjectThread * );
    String timespan( const IntegerSet & ) const;

private:
    class ArchiveMailboxData * d;
};


#endif
