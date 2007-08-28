// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "ustringlist.h"

#include "dict.h"


/*! \class UStringList ustringlist.h

    The UStringList class is a List of UString object, offering a few
    convenience functions such as join() and removeDuplicates().
*/


/*! Constructs an empty List of (pointers to) UString objects. */

UStringList::UStringList()
{
}


/*! \fn void UStringList::append( UString * s )

    Appends the UString \a s to this UStringList. (Inline reimplementation
    to work around the shadowing rules of C++.)
*/



/*! This version of append() makes a copy of \a s and appends that
    copy to the list.
*/

void UStringList::append( const UString & s )
{
    List<UString>::append( new UString( s ) );
}


/*! Returns a string containing every UString in this list, with \a
    separator between the items.

    If this List isEmpty(), this function returns an empty UString.
*/

UString UStringList::join( const UString & separator )
{
    UString r;
    Iterator it( this );
    uint l = 0;
    while ( it ) {
        l = l + it->length() + separator.length();
        ++it;
    }
    r.reserve( l );
    it = first();
    while ( it ) {
        r.append( *it );
        ++it;
        if ( it )
            r.append( separator );
    }
    return r;
}


/*! Returns a string containing every UString in this list, with \a
    separator between the items.

    If this List isEmpty(), this function returns an empty UString.
*/

UString UStringList::join( const char * separator )
{
    UString s;
    s.append( separator );
    return join( separator );
}



/*! This function splits \a s on the separator \a c, and returns a non-0
    pointer to a list of the resulting strings. Consecutive occurrences
    of \a c cause the list to contain empty elements.
*/

UStringList *UStringList::split( char c, const UString &s )
{
    UStringList *l = new UStringList;

    int n = 0;
    int last = 0;
    do {
        UString w;
        n = s.find( c, last );
        if ( n >= 0 ) {
            w = s.mid( last, n-last );
            n++;
        }
        else {
            w = s.mid( last );
        }
        last = n;
        l->append( w );
    }
    while ( last > 0 );

    return l;
}


/*! Returns true if \a s occurs in this string list, and false if not. */

bool UStringList::contains( const UString & s ) const
{
    Iterator i( this );
    while ( i && s != *i )
        ++i;
    if ( i )
        return true;
    return false;
}
