// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STRINGLIST_H
#define STRINGLIST_H

#include "list.h"
#include "string.h"

class StringList: public List<String>
{
public:
    StringList();

    void append( String * s ) { List<String>::append( s ); }
    void append( const String & );
    void append( const char * );

    String join( const String & );
};

#endif
