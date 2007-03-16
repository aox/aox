// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef LISTIDFIELD_H
#define LISTIDFIELD_H

#include "field.h"


class Parser822;


class ListIdField
    : public HeaderField
{
public:
    ListIdField();

    void parse( const String & );
};


#endif
