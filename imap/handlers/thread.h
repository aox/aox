// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef THREAD_H
#define THREAD_H

#include "search.h"
#include "imapresponse.h"


class Thread
    : public Search
{
public:
    Thread( bool );
    void parse();
    void execute();

private:
    class ThreadData * d;
};


class ThreadResponse
    : public ImapResponse
{
public:
    ThreadResponse( class ThreadData * );
    EString text() const;

private:
    class ThreadData * d;
};


#endif
