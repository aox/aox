// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef ANONYMISE_H
#define ANONYMISE_H

#include "aoxcommand.h"


class Anonymise
    : public AoxCommand
{
public:
    Anonymise( EStringList * );
    void execute();
};


#endif
