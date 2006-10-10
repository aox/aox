// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef SECTION_H
#define SECTION_H

#include "global.h"


class Section
    : public Garbage
{
public:
    Section()
        : binary( false ),
          partial( false ), offset( 0 ), length( UINT_MAX ),
          needsHeader( true ), needsBody( true )
    {}

    String id;
    String item;
    String part;
    StringList fields;
    bool binary;
    bool partial;
    uint offset;
    uint length;

    bool needsHeader;
    bool needsBody;
    String error;
};


#endif
