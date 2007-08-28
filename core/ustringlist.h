// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef USTRINGLIST_H
#define USTRINGLIST_H

#include "list.h"
#include "ustring.h"


class UStringList
    : public List< UString >
{
public:
    UStringList();

    void append( UString * s ) { List<UString>::append( s ); }
    void append( const UString & );
    void append( const char * );

    void removeDuplicates( bool = true );
    bool contains( const UString & ) const;

    UString join( const UString & );
    static UStringList *split( char, const UString & );
};


#endif
