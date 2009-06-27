// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SORT_H
#define SORT_H

#include "search.h"
#include "list.h"


class Sort
    : public Search
{
public:
    Sort( bool );
    void parse();
    void execute();

private:
    class SortData * d;
};


class ImapSortResponse
    : public ImapResponse
{
public:
    ImapSortResponse( ImapSession *, List<uint> *, bool );
    EString text() const;

private:
    List<uint> * r;
    bool u;
};


#endif
