// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#ifndef SECTION_H
#define SECTION_H

#include "global.h"
#include "estring.h"
#include "estringlist.h"


class Section
    : public Garbage
{
public:
    Section()
        : binary( false ),
          partial( false ), offset( 0 ), length( UINT_MAX ),
          needsAddresses( false ), needsHeader( false ), needsBody( false )
    {}

    EString id;
    EString item;
    EString part;
    EStringList fields;
    bool binary;
    bool partial;
    uint offset;
    uint length;

    bool needsAddresses;
    bool needsHeader;
    bool needsBody;
    EString error;
};


#endif
