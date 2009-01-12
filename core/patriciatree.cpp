// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "patriciatree.h"

/*! \class PatriciaTree patriciatree.h

    Implements a modified Patricia Tree.

    Our implementation of this data structure stores objects of a
    single type based on a bit string. The bit string can have any
    length, it need not be an integer number of bytes. Our
    implementation differs from that described by Knuth in supporting
    keys that are prefixes of other keys.

    The class is optimised for fast retrieval. Inserting is a little
    slower.

    There are three common public operations: insert(), find() and
    remove(). There's also a clear(), which is fast but relies on GC
    to tidy up slowly later.

    A few subclasses (with bad names for historical reasons) use
    PatriciaTree to provide maps from integers and strings, Dict,
    UDict and Map.

    Two virtual functions, node() and free(), must be reimplemented in
    order to avoid relying on Allocator.
*/


/*! \fn PatriciaTree::PatriciaTree()
  
    Creates an empty tree.
*/



/*! \fn void PatriciaTree::find( const char * k, uint l )
  
    Looks up the item with key \a k of length \a l. A one-byte key
    must have \a l 8.

    Returns 0 if there is no such item.
*/


/*! \fn T * PatriciaTree::remove( const char * k, uint l )
  
    Removes the item with key \a k of length \a l. A one-byte key
    must have \a l 8.

    Returns a pointer to the removed item, or a null pointer if there
    was no such item in the tree.
*/


/*! \fn void PatriciaTree::insert( const char * k, uint l, T * t )
  
    Inserts the item \a t using key \a k of length \a l. A one-byte key
    must have \a l 8.

    If there already was an item with that key, the old item is
    silently forgotten.
*/

/*! \fn bool PatriciaTree::isEmpty()

    Returns true if the tree is empty, and false otherwise. Fast (much
    faster than !count()).
*/

/*! \fn uint PatriciaTree::count() const

    Returns the number of items in the tree.
*/


/*! \fn void PatriciaTree::clear()
  
    Instantly forgets everything in the tree.
*/


/*! \fn void PatriciaTree::free( PatriciaTree::Node * n )
  
    This virtual function is called when \a n is no longer needed.
*/
/*! \fn PatriciaTree::Node * PatriciaTree::node()
  
    This virtual function allocates and returns a new tree node.
*/
