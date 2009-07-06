// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ARCHIVESEARCH_H
#define ARCHIVESEARCH_H

#include "pagecomponent.h"


class ArchiveSearch
    : public PageComponent
{
public:
    ArchiveSearch( class Link * );

    void execute();

private:
    class ArchiveSearchData * d;

    void parseTerms();
    void sendQueries();
    void setTitle();
    EString searchTerms() const;
    void computeResultSets();
    bool queriesDone() const;

    EString shortishResultList() const;
    EString middlingResultList() const;
    EString looongResultList() const;
};


#endif
