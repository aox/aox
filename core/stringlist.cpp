// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "stringlist.h"


/*! \class StringList stringlist.h

    The StringList class is a List of String object, offering a few
    convenience functions, most importantly join().
*/


/*! Constructs an empty List of (pointers to) String objects. */

StringList::StringList()
{
}


/*! \fn void StringList::append( String * s )

    Reimplemented (as an inline) to work around the shadowing rules of C++.
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
    Iterator it( first() );
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
