// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ARCHIVEMESSAGE_H
#define ARCHIVEMESSAGE_H

#include "pagecomponent.h"
#include "field.h"


class Message;


class ArchiveMessage
    : public PageComponent
{
public:
    ArchiveMessage( class Link * );

    void execute();

    void setLinkToThread( bool );
    bool linkToThread() const;

private:
    class ArchiveMessageData * d;

private:
    static EString addressField( Message *, HeaderField::Type );
    //static EString twoLines( Message * );

    EString bodypart( Message *, uint, class Bodypart * );
    EString message( Message *, Message * );
    EString jsToggle( const EString &, bool, const EString &, const EString & );
    EString date( class Date *, const EString & ) const;
};


#endif
