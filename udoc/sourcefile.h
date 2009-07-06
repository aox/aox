// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SOURCEFILE_H
#define SOURCEFILE_H

#include "file.h"


class Parser;
class Function;


class SourceFile: public File
{
public:
    SourceFile( const EString & );

    void parse();

private:
    Function * function( Parser * );
};


#endif
