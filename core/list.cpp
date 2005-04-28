// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "list.h"

#include "string.h"


/*! \class List list.h
    A generic template class for a doubly-linked list of pointers-to-T.

    A new List isEmpty(), and elements can be added using append(),
    prepend() or insert(). The list knows its first() and last()
    elements, and can find() specific ones. You can take() any
    element away, as well as count() or clear() the entire List.

    This class never deletes the List elements themselves. That is the
    caller's responsibility.

    There is also a SortedList template.
*/


/*! \fn List::List()
    Creates an empty list.
*/


/*! \fn List::~List()
    Destroys the list without affecting its contents.
*/


/*! \fn bool List::isEmpty() const
    Returns true only if the List contains no elements.
*/


/*! \fn uint List::count() const
    Returns the number of elements in the list.
*/


/*! \fn void List::clear()
    Empties the list by simply forgetting about all of its elements.
*/


/*! \fn Iterator &List::first() const
    Returns an Iterator that points to the first element in the List.
*/


/*! \fn Iterator &List::last() const
    Returns an Iterator that points to the last element in the List.
*/


/*! \fn Iterator &List::end() const
    Returns an Iterator that points beyond the last element in the List.
    In a boolean context, this Iterator evaluates to false.
*/


/*! \fn T *List::take( Iterator &i )
    Removes the element pointed to by \a i from the List, and returns it
    after incrementing \a i to point to the next element in the List. If
    \a i does not point to a list element (e.g. end()), take() returns 0
    and does nothing.
*/


/*! \fn T *List::pop()
    Removes the last element from the List and returns it.
*/


/*! \fn T *List::shift()
    Removes the first element from the List and returns it.

*/


/*! \fn void List::insert( const Iterator &i, T *d )
    Inserts \a d before the element pointed to by \a i.
*/


/*! \fn void List::append( T *d )
    Adds \a d to the end of the List.
*/


/*! \fn void List::prepend( T *d )
    Adds \a d to the beginning of the List.

*/


/*! \fn Iterator &List::find( const T *d )
    Returns an Iterator pointing to the position of the first element in
    the List that is equal to \a d.
*/


/*! \fn Iterator &List::find( const String &d )
    Returns an Iterator pointing to the position of the first element in
    the List that points to an object that is equal to the String \a d.

*/

/*! \fn T *List::remove( const T *d )
    This function is equivalent to take( find( d ) ), in that it finds
    the position of the first element in the List equal to \a d, then
    removes that element. Its advantage is that it performs no memory
    allocation. It returns a pointer to the removed element, or 0 if
    it was not found in the List.
*/


/*! \class List::Iterator list.h
    This class can be used to iterate over the elements of a List<T>.

    An Iterator behaves like a pointer to an element in the List. In a
    boolean context, an Iterator is true if it points to an element in
    the List, and false if it has been incremented or decremented past
    one of its ends.

    If the Iterator is true, it can be dereferenced (with * and ->) or
    incremented to point to the next element, or decremented to point
    to the previous one. It can also be compared to another Iterator.

    XXX: What happens if a List contains null pointers?
*/


/*! \class SortedList list.h
    A List of pointers-to-T sorted in an ascending order defined by T.

    This is a subclass of the generic List<T> that uses T::operator <=()
    to insert each element in ascending order, after any elements it is
    equal to. It behaves like the generic List<T> in all other respects.

    This sorted insert behaviour occurs only when the insert() function
    is passed a single pointer. Using prepend(), append(), and insert()
    with an Iterator will still insert elements into specific positions
    irrespective of their value.
*/

/*! \fn Iterator & SortedList::insert( T *d )
    This function inserts the object \a d into a SortedList, and returns
    a reference to an Iterator pointing to it.
*/


