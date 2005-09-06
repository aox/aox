// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTML_H
#define HTML_H

#include "string.h"


class HTML
    : public Garbage
{
public:
    static String asText( String );
};


#endif
