// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "dict.h"

#include "allocator.h"


class DictBaseData
    : public Garbage
{
public:
    DictBaseData():
        size( 0 ), buckets( 0 )
    {}

    class Node
        : public Garbage
    {
    public:
        Node( Node * n, uint h, void * v, const String & s )
            : next( n ), hash( h ), data( v ), key( s ) {}
        Node * next;
        uint hash;
        void * data;
        String key;
    };

    uint size;

    Node** buckets;
};


/*! \class Dict dict.h
  The Dict class provides a simple string-to-object dictionary.

  It is optimized for simplicity, and for extremely fast lookups when
  the number of items can be estimated in advance. Its other
  facilities are somewhat primitive. There is no iterator, for
  example, and no way to remove an object from the dictionary.

  An item can be added with insert(), retrieved with find() or the
  presence of an item can be tested with contains(). That's it.
*/


/*! \fn Dict::Dict()
    Creates an empty dictionary.
*/

/*! \fn T * Dict::find( const String &s ) const
    Looks for the object identified by \a s in the dictionary, and
    returns a pointer to it (or 0 if no such object was found).
*/

/*! \fn void Dict::insert( const String &s, T* r )
    Inserts the object \a r into the dictionary, identified by the
    string \a s.
*/

/*! \fn bool Dict::contains( const String &s ) const
    Returns true if an object identified by \a s exists in the
    dictionary, and false otherwise.
*/


/*! \class DictBase dict.h
  The DictBase class is the foundation for Dict.

  It has no own API, it merely provides the member functions used in
  Dict. Dict, as befits a template, has only small, inline
  members. Whenever something big is required, Dict calls a DictBase
  function.
*/


/*! Constructs an empty dictionary. */

DictBase::DictBase()
    : d( new DictBaseData )
{
    resize( 257 );
}


/*! Returns true only if the Dict contains the key \a s.
*/

bool DictBase::contains( const String &s ) const
{
    // This duplicates the code in find(), mostly because there isn't
    // very much of it.
    uint h = hash( s );
    DictBaseData::Node * n = d->buckets[h % d->size];
    while ( n && ( n->hash != h || n->key != s ) )
        n = n->next;

    if ( n )
        return true;
    return false;
}


/*! Returns a pointer to the object whose key is \a s, or a null
    pointer if there is no such object.
*/

void * DictBase::find( const String & s ) const
{
    uint h = hash( s );
    DictBaseData::Node * n = d->buckets[h % d->size];
    while ( n && ( n->hash != h || n->key != s ) )
        n = n->next;
    if ( n )
        return n->data;
    return 0;
}


/*! Inserts \a r to the dictionary based on key \a s, replacing any
    previous object with key \a s.

    The previous object is not deleted, merely removed from the
    dictionary.
*/

void DictBase::insert( const String & s, void* r )
{
    uint h = hash( s );
    DictBaseData::Node * n = d->buckets[h % d->size];
    while ( n && ( n->hash != h || n->key != s ) )
        n = n->next;
    if ( !n ) {
        DictBaseData::Node * next = d->buckets[h % d->size];
        n = new DictBaseData::Node( next, h, r, s );
        d->buckets[h % d->size] = n;
    }
    n->data = r;
}



/*! Removes the object with key \a s from the dictionary. The object
    is not deleted, merely removed from the dictionary.

    If there is no such object, insert() does nothing.
*/

void * DictBase::take( const String & s )
{
    uint h = hash( s );
    DictBaseData::Node * n = d->buckets[h % d->size];
    if ( !n )
        return 0;
    if ( n->hash == h && n->key == s ) {
        d->buckets[h % d->size] = n->next;
        return n->data;
    }
    DictBaseData::Node * p = 0;
    while ( n && ( n->hash != h || n->key != s ) ) {
        p = n;
        n = n->next;
    }
    if ( p && n )
        p->next = n->next;
    if ( n )
        return n->data;
    return 0;
}


/*! Returns a 32-bit has of the string \a key. \a key is viewed as a
    series of numbers, so the algorithm can easily be used on either
    UString or String.

    This code uses the algorithm djb described on comp.lang.c in 1990,
    message-id <6429:Dec500:37:2890@kramden.acf.nyu.edu>.

    http://www.cse.yorku.ca/~oz/hash.html contains a good overview of
    simple hash functions.
*/

uint DictBase::hash( const String & key )
{
    uint h = 5381;
    uint i = 0;
    while ( i < key.length() ) {
        // the original used + key[i], djb later switched to xor.
        h = ((h << 5) + h) ^ key[i];
        i++;
    }
    return h;
}


/*! Changes the number of buckets in the dictionary to \a size, resorting
    all the contained objects. This function is necessarily slow.
*/

void DictBase::resize( uint size )
{
    DictBaseData::Node ** buckets = d->buckets;
    d->buckets
        = (DictBaseData::Node **)
        Allocator::alloc( size * sizeof(DictBaseData::Node*),
                          size );
    uint i = 0;
    while ( i < size ) {
        d->buckets[i] = 0;
        i++;
    }
    uint oldSize = d->size;
    d->size = size;

    i = 0;
    while ( i < oldSize ) {
        DictBaseData::Node * n = buckets[i];
        while ( n ) {
            insert( n->key, n->data );
            n = n->next;
        }
        i++;
    }
}


/*! Returns a list of all the keys in this dictionary. */

StringList DictBase::keys() const
{
    StringList r;
    uint b = 0;
    while ( b < d->size ) {
        DictBaseData::Node * n = d->buckets[b];
        while ( n ) {
            r.append( n->key );
            n = n->next;
        }
        b++;
    }
    return r;
}


