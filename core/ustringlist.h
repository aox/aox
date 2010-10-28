// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

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

    void removeDuplicates( bool = true );
    bool contains( const UString & ) const;

    UString join( const UString & );
    UString join( const char * );
    static UStringList *split( char, const UString & );

    UStringList &operator =( const UStringList & other ) {
        clear();
        Iterator o( other );
        while ( o ) {
            append( o );
            ++o;
        }
        return *this;
    }
};


#endif
