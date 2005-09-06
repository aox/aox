// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef HTML_H
#define HTML_H

#include "ustring.h"


class HTML
    : public Garbage
{
public:
    static UString asText( const UString & );
};


#endif
