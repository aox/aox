// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef REPARSE_H
#define REPARSE_H

#include "aoxcommand.h"


class Reparse
    : public AoxCommand
{
public:
    Reparse( EStringList * );
    void execute();

    EString writeErrorCopy( const EString & );

private:
    class ReparseData * d;
};


#endif
