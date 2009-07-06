// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef RETENTION_H
#define RETENTION_H

#include "aoxcommand.h"


class RetainMessages
    : public AoxCommand
{
public:
    RetainMessages( EStringList *, bool = true );

    void execute();

private:
    class RetainMessagesData * d;
};


class DeleteMessages
    : public RetainMessages
{
public:
    DeleteMessages( EStringList * );
};


class ShowRetention
    : public AoxCommand
{
public:
    ShowRetention( EStringList * );

    void execute();

private:
    class ShowRetentionData * d;
};


#endif
