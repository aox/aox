// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "estringlist.h"

#include "dict.h"


/*! \class EStringList estringlist.h

    The EStringList class is a List of EString object, offering a few
    convenience functions such as join() and removeDuplicates().
*/


/*! Constructs an empty List of (pointers to) EString objects. */

EStringList::EStringList()
{
}


/*! \fn void EStringList::append( EString * s )

    Appends the EString \a s to this EStringList. (Inline reimplementation
    to work around the shadowing rules of C++.)
*/



/*! This version of append() makes a copy of \a s and appends that
    copy to the list.
*/

void EStringList::append( const EString & s )
{
    List<EString>::append( new EString( s ) );
}


/*! This version of append() makes a EString copy of \a s and appends
    that copy to the list.
*/

void EStringList::append( const char * s )
{
    List<EString>::append( new EString( s ) );
}


/*! Returns a string containing every EString in this list, with \a
    separator between the items.

    If this List isEmpty(), this function returns an empty EString.
*/

EString EStringList::join( const EString & separator ) const
{
    EString r;
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


/*! This function splits \a s on the separator \a c, and returns a non-0
    pointer to a list of the resulting strings. Consecutive occurrences
    of \a c cause the list to contain empty elements.
*/

EStringList *EStringList::split( char c, const EString &s )
{
    EStringList *l = new EStringList;

    int n = 0;
    int last = 0;
    do {
        EString w;
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


/*! Removes duplicate entries from the list. If \a caseSensitive is
    true (this is the default), strings are compared exactly. If \a
    caseSensitive is false, ASCII A-Z are treated as equal to a-z.

    When two more more strings are equal, removeDuplicates() leaves
    the first and removes the second and later copies.
*/

void EStringList::removeDuplicates( bool caseSensitive )
{
    Dict<uint> e;
    uint tmp = 1;
    Iterator i( this );
    while ( i ) {
        EString s = *i;
        if ( !caseSensitive )
            s = s.lower();
        if ( e.contains( s ) ) {
            take( i );
        }
        else {
            ++i;
            e.insert( s, &tmp );
        }
    }
}


/*! Returns true if \a s occurs in this string list, and false if not. */

bool EStringList::contains( const EString & s ) const
{
    Iterator i( this );
    while ( i && s != *i )
        ++i;
    if ( i )
        return true;
    return false;
}
