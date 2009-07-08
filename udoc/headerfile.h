// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef HEADERFILE_H
#define HEADERFILE_H

#include "file.h"


class HeaderFile: public File
{
public:
    HeaderFile( const EString & );

    static HeaderFile * find( const EString & );

    void parse();
};


#endif
