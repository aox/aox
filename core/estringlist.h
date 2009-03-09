// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#ifndef STRINGLIST_H
#define STRINGLIST_H

#include "list.h"
#include "estring.h"


class EStringList
    : public List< EString >
{
public:
    EStringList();

    void append( EString * s ) { List<EString>::append( s ); }
    void append( const EString & );
    void append( const char * );
    void append( const EStringList & l ) { List<EString>::append( l ); }

    void removeDuplicates( bool = true );
    bool contains( const EString & ) const;

    EStringList * sorted() const;

    EString join( const EString & ) const;
    static EStringList *split( char, const EString & );
};


#endif
