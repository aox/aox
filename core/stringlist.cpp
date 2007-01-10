// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "stringlist.h"

#include "dict.h"


/*! \class StringList stringlist.h

    The StringList class is a List of String object, offering a few
    convenience functions such as join() and removeDuplicates().
*/


/*! Constructs an empty List of (pointers to) String objects. */

StringList::StringList()
{
}


/*! \fn void StringList::append( String * s )

    Appends the String \a s to this StringList. (Inline reimplementation
    to work around the shadowing rules of C++.)
*/



/*! This version of append() makes a copy of \a s and appends that
    copy to the list.
*/

void StringList::append( const String & s )
{
    List<String>::append( new String( s ) );
}


/*! This version of append() makes a String copy of \a s and appends
    that copy to the list.
*/

void StringList::append( const char * s )
{
    List<String>::append( new String( s ) );
}


/*! Returns a string containing every String in this list, with \a
    separator between the items.

    If this List isEmpty(), this function returns an empty String.
*/

String StringList::join( const String & separator )
{
    String r;
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

StringList *StringList::split( char c, const String &s )
{
    StringList *l = new StringList;

    int n = 0;
    int last = 0;
    do {
        String w;
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

void StringList::removeDuplicates( bool caseSensitive )
{
    Dict<uint> e;
    uint tmp = 1;
    Iterator i( this );
    while ( i ) {
        String s = *i;
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

bool StringList::contains( const String & s ) const
{
    Iterator i( this );
    while ( i && s != *i )
        ++i;
    if ( i )
        return true;
    return false;
}
