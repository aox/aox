// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef QUEUE_H
#define QUEUE_H

#include "aoxcommand.h"


class ShowQueue
    : public AoxCommand
{
public:
    ShowQueue( EStringList * );
    void execute();

private:
    class Query * q;
    class Query * qr;
};


class FlushQueue
    : public AoxCommand
{
public:
    FlushQueue( EStringList * );
    void execute();

private:
    class Transaction * t;
};


#endif
