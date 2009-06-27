// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef LISTIDFIELD_H
#define LISTIDFIELD_H

#include "field.h"


class EmailParser;


class ListIdField
    : public HeaderField
{
public:
    ListIdField();

    void parse( const EString & );
};


#endif
