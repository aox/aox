// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef IMAPURLFETCHER_H
#define IMAPURLFETCHER_H

#include "list.h"
#include "event.h"
#include "imapurl.h"


class ImapUrlFetcher
    : public EventHandler
{
public:
    ImapUrlFetcher( List<ImapUrl> *, EventHandler * );

    void execute();
    bool done() const;
    bool failed() const;
    EString badUrl() const;
    EString error() const;

private:
    class IufData *d;

    void setError( const EString &, const EString & );
};


#endif
