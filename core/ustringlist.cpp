// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "ustringlist.h"

#include "dict.h"


/*! \class UStringList ustringlist.h

    The UStringList class is a List of UString object, offering a few
    convenience functions such as join() and split().
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


/*! \fn void UStringList::append( const UStringList & other )
    Appends each string in the given list \a other to this one.
*/


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
    return join( s );
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


/*! Removes duplicate entries from the list. If \a caseSensitive is
    true (this is the default), strings are compared exactly. If \a
    caseSensitive is false, ASCII A-Z are treated as equal to a-z.

    When two more more strings are equal, removeDuplicates() leaves
    the first and removes the second and later copies.
*/

void UStringList::removeDuplicates( bool caseSensitive )
{
    UDict<uint> e;
    uint tmp = 1;
    Iterator i( this );
    while ( i ) {
        UString s = *i;
        if ( !caseSensitive )
            s = s.titlecased();
        if ( e.contains( s ) ) {
            take( i );
        }
        else {
            ++i;
            e.insert( s, &tmp );
        }
    }
}
