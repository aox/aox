// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STRINGLIST_H
#define STRINGLIST_H

#include "list.h"
#include "estring.h"


class StringList
    : public List< String >
{
public:
    StringList();

    void append( String * s ) { List<String>::append( s ); }
    void append( const String & );
    void append( const char * );

    void removeDuplicates( bool = true );
    bool contains( const String & ) const;

    String join( const String & ) const;
    static StringList *split( char, const String & );
};


#endif
