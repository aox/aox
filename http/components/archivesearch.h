// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
    String searchTerms() const;
    void computeResultSets();
    bool queriesDone() const;

    String shortishResultList() const;
    String middlingResultList() const;
    String looongResultList() const;
};


#endif
