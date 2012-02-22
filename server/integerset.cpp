// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "integerset.h"

#include "estringlist.h"
#include "map.h"


static inline uint bitsSet( uint b )
{
    uint r = 0;
    while ( b ) {
        switch ( b & 15 ) {
        case 0:
            r += 0;
            break;
        case 1:
        case 2:
        case 4:
        case 8:
            r += 1;
            break;
        case 3:
        case 5:
        case 6:
        case 9:
        case 10:
        case 12:
            r += 2;
            break;
        case 7:
        case 11:
        case 13:
        case 14:
            r += 3;
            break;
        case 15:
            r += 4;
            break;
        }
        b >>= 4;
    }
    return r;
};


static const uint BlockSize = 8192;
static const uint BitsPerUint = 8 * sizeof(uint);
static const uint ArraySize = (BlockSize + BitsPerUint - 1) / BitsPerUint;


class SetData
    : public Garbage
{
public:
    SetData() {}

    class Block
        : public Garbage
    {
    public:
        Block( uint s )
            : Garbage(), start( s ), count( 0 ) {
            setFirstNonPointer( &start );
            uint i = 0;
            while ( i < ArraySize )
                contents[i++] = 0;
        }
        Block( const Block & other )
            : Garbage(), start( other.start ), count( other.count ) {
            setFirstNonPointer( &start );
            uint i = 0;
            while ( i < ArraySize ) {
                contents[i] = other.contents[i];
                ++i;
            }
        }

        uint start;
        uint count;
        uint contents[ArraySize];

        inline void insert( uint n ) {
            if ( n < start )
                return;
            uint i = n - start;
            if ( i >= BlockSize )
                return;

            if ( !(contents[i/BitsPerUint] & 1 << ( i % BitsPerUint )) )
                count++;
            contents[i/BitsPerUint] |= 1 << ( i % BitsPerUint );
        }

        void recount() {
            count = 0;
            uint i = 0;
            while ( i < ArraySize )
                count += bitsSet( contents[i++] );
        }

        void merge( Block * other ) {
            count = 0;
            uint i = 0;
            while ( i < ArraySize ) {
                contents[i] |= other->contents[i];
                ++i;
            }
        }
    };

    Map<Block> b;
};


/*! \class IntegerSet integerset.h
    This class contains a set of integers.

    A IntegerSet is just a set of nonnegative integers. It can add new
    members to the set, find its members by value() or index() (sorted
    by size, with 1 first), look for the largest contained number, and
    produce an SQL "where" clause matching its contents.
*/


/*! Constructs an empty set. */

IntegerSet::IntegerSet()
{
    d = new SetData;
}


/*! Constructs a set that's an exact copy of \a other. This
    constructor is a little expensive, both in time and space.
*/

IntegerSet::IntegerSet( const IntegerSet & other )
    : Garbage()
{
    d = 0;
    *this = other;
}


IntegerSet& IntegerSet::operator=( const IntegerSet & other )
{
    if ( d == other.d )
        return *this;

    d = new SetData;
    Map<SetData::Block>::Iterator i( other.d->b );
    while ( i ) {
        d->b.insert( i->start, new SetData::Block( *i ) );
        ++i;
    }
    return *this;
}


/*! Adds all numbers between \a n1 and \a n2 to the set, including
    both \a n1 and \a n2.

    \a n1 and \a n2 must both be nonzero.
*/

void IntegerSet::add( uint n1, uint n2 )
{
    if ( n2 < n1 ) {
        add( n2, n1 );
        return;
    }

    if ( !n1 ) {
        if ( n2 )
            add( 1, n2 );
        return;
    }

    uint n = n1;
    uint s = n - (n%BlockSize);
    SetData::Block * b = d->b.find( s );
    if ( !b ) {
        b = new SetData::Block( s );
        d->b.insert( s, b );
    }
    b->insert( n );
    while ( n < n2 ) {
        ++n;
        if ( s != n - (n%BlockSize) ) {
            s = n - (n%BlockSize);
            b = d->b.find( s );
            if ( !b ) {
                b = new SetData::Block( s );
                d->b.insert( s, b );
            }
        }
        b->insert( n );
    }
}


/*! Adds each value in \a set to this set. */

void IntegerSet::add( const IntegerSet & set )
{
    if ( isEmpty() ) {
        *this = set;
        return;
    }
    Map<SetData::Block>::Iterator i( set.d->b );
    while( i ) {
        SetData::Block * b = d->b.find( i->start );
        if ( b )
            b->merge( i );
        else
            d->b.insert( i->start, new SetData::Block( *i ) );

        ++i;
    }
}


/*! Returns the smallest UID in this IntegerSet, or 0 if the set is
    empty.
*/

uint IntegerSet::smallest() const
{
    return value( 1 );
}


/*! Returns the largest number in this IntegerSet, or 0 if the set is
    empty.
*/

uint IntegerSet::largest() const
{
    SetData::Block * b = d->b.last();
    if ( !b )
        return 0;
    uint i = ArraySize - 1;
    while ( i && !b->contents[i] )
        i--;
    uint x = b->contents[i];
    uint j = BitsPerUint-1;
    while ( !(x & 1 << j) )
        j--;
    return b->start + i * BitsPerUint + j;
}


/*! Returns the number of numbers in this IntegerSet. */

uint IntegerSet::count() const
{
    recount();
    uint c = 0;
    Map<SetData::Block>::Iterator i( d->b );
    while ( i ) {
        c += i->count;
        ++i;
    }
    return c;
}


/*! Returns true if the set is empty, and false if not. */

bool IntegerSet::isEmpty() const
{
    return d->b.isEmpty();
}


/*! Returns the value at \a index, or 0 if \a index is greater than
    count().

    If this set contains the UIDs in a mailbox, this function converts
    from MSNs to UIDs. See Session::uid().
*/

uint IntegerSet::value( uint index ) const
{
    if ( !index )
        return 0;
    recount();
    uint c = 0;
    Map<SetData::Block>::Iterator i( d->b );
    while ( i && c + i->count < index ) {
        c += i->count;
        ++i;
    }
    if ( !i )
        return 0;

    uint bs = bitsSet( i->contents[0] );
    uint n = 0;
    while ( c + bs < index ) {
        c += bs;
        n++;
        bs = bitsSet( i->contents[n] );
    }
    uint j = 0;
    while ( c < index && j < BitsPerUint ) {
        if ( i->contents[n] & ( 1 << j ) )
            c++;
        if ( c < index )
            j++;
    }
    return i->start + n*BitsPerUint + j;
}


/*! Returns the index of \a value index, or 0 if \a value is not in
    this Set.

    If this set contains the UIDs in a mailbox, this function converts
    from UIDs to MSNs. See Session::msn().
*/

uint IntegerSet::index( uint value ) const
{
    recount();
    uint i = 0;
    Map<SetData::Block>::Iterator b( d->b );
    while ( b && b->start + BlockSize - 1 < value ) {
        i += b->count;
        ++b;
    }
    if ( !b )
        return 0;

    if ( b->start > value )
        return 0;

    uint vi = (value-b->start)/BitsPerUint;
    if ( !(b->contents[vi] & 1 << (value%BitsPerUint)) )
        return 0;
    uint n = 0;
    while ( n < vi ) {
        i += bitsSet( b->contents[n] );
        n++;
    }
    i += bitsSet ( b->contents[vi] & ~( 0xfffffffe << (value%BitsPerUint) ) );
    return i;
}


/*! Returns true if \a value is present in this set, and false if not. */

bool IntegerSet::contains( uint value ) const
{
    SetData::Block * b = d->b.find( value - (value%BlockSize) );
    if ( !b )
        return false;
    uint n = value%BlockSize;
    if ( b->contents[n/BitsPerUint] & ( 1 << n%BitsPerUint ) )
        return true;
    return false;
}


/*! Removes \a value from this set. Does nothing unless \a value is
    present in the set.*/

void IntegerSet::remove( uint value )
{
    SetData::Block * b = d->b.find( value - (value%BlockSize) );
    if ( !b )
        return;

    uint i = value - b->start;
    if ( i >= BlockSize )
        return;

    if ( ! ( (b->contents[i/BitsPerUint] & 1 << ( i % BitsPerUint )) ) )
        return;

    b->contents[i/BitsPerUint] &= ~(1 << ( i % BitsPerUint ) );
    if ( b->count ) {
        b->count--;
        if ( !b->count )
            d->b.remove( b->start );
    }
    else {
        recount();
    }
}


/*! Removes \a v1, \a v2 and all values between them from this set. */

void IntegerSet::remove( uint v1, uint v2 )
{
    IntegerSet r;
    r.add( v1, v2 );
    remove( r );
}


/*! Removes all values contained in \a other from this set. */

void IntegerSet::remove( const IntegerSet & other )
{
    Map<SetData::Block>::Iterator mine( d->b );
    Map<SetData::Block>::Iterator hers( other.d->b );
    while ( mine && hers ) {
        while ( mine && mine->start < hers->start )
            ++mine;
        if ( mine )
            while ( hers && hers->start < mine->start )
                ++hers;
        if ( mine && hers ) {
            uint i = 0;
            uint u = 0;
            uint s = mine->start;
            while ( i < ArraySize ) {
                mine->contents[i] &= ~ hers->contents[i];
                u |= mine->contents[i];
                i++;
            }
            mine->count = 0;
            ++mine;
            ++hers;
            if ( !u )
                d->b.remove( s );
        }
    }
}


/*! Returns a set containing all values which are contained in both
    this IntegerSet and in \a other. */

IntegerSet IntegerSet::intersection( const IntegerSet & other ) const
{
    IntegerSet r;
    Map<SetData::Block>::Iterator mine( d->b );
    Map<SetData::Block>::Iterator hers( other.d->b );
    while ( mine && hers ) {
        while ( mine && mine->start < hers->start )
            ++mine;
        if ( mine )
            while ( hers && hers->start < mine->start )
                ++hers;
        if ( mine && hers ) {
            SetData::Block * b = new SetData::Block( mine->start );
            uint u = 0;
            uint i = 0;
            while ( i < ArraySize ) {
                b->contents[i] = mine->contents[i] & hers->contents[i];
                u |= b->contents[i];
                i++;
            }
            if ( u )
                r.d->b.insert( b->start, b );
            ++mine;
            ++hers;
        }
    }
    return r;
}


/*! Removes all numbers from this set. */

void IntegerSet::clear()
{
    d = new SetData;
}


static void addRange( EString & r, uint s, uint e )
{
    if ( !r.isEmpty() )
        r.append( ',' );
    r.appendNumber( s );
    if ( e <= s )
        return;
    if ( e == s + 1 )
        r.append( ',' );
    else
        r.append( ':' );
    r.appendNumber( e );
}


/*! Returns the contents of this set in IMAP syntax. The shortest
    possible representation is returned, with strictly increasing
    values, without repetitions, with ":" and "," as necessary.

    If the set is empty, so is the returned string.
*/

EString IntegerSet::set() const
{
    EString r;
    r.reserve( 2222 );
    uint s = 0;
    uint e = 0;

    Map<SetData::Block>::Iterator it( d->b );
    while ( it ) {
        uint v = it->start;
        uint n = 0;
        while ( n < ArraySize ) {
            uint j = 0;
            uint b = it->contents[n];
            if ( b ) {
                while ( j < BitsPerUint ) {
                    if ( b & ( 1 << j ) ) {
                        if ( !e ) {
                            s = v + j;
                            e = s;
                        }
                        else if ( e + 1 < v + j ) {
                            addRange( r, s, e );
                            s = v + j;
                            e = s;
                        }
                        else {
                            e = v + j;
                        }
                    }
                    j++;
                }
            }
            n++;
            v += BitsPerUint;
        }
        ++it;
    }
    if ( e )
        addRange( r, s, e );
    return r;
}


/*! Returns the contents of this set as a comma-separated list of
    decimal numbers.
*/

EString IntegerSet::csl() const
{
    EString r;
    r.reserve( 2222 );

    Map<SetData::Block>::Iterator it( d->b );
    while ( it ) {
        uint n = 0;
        while ( n < ArraySize ) {
            uint j = 0;
            uint b = it->contents[n];
            if ( b ) {
                while ( j < BitsPerUint ) {
                    if ( b & ( 1 << j ) ) {
                        if ( !r.isEmpty() )
                            r.append( ',' );
                        r.appendNumber( it->start + n * BitsPerUint + j );
                    }
                    j++;
                }
            }
            n++;
        }
        ++it;
    }
    return r;
}


/*! This private helper ensures that all blocks have an accurate count
    of set bits, and that no blocks are empty.
*/

void IntegerSet::recount() const
{
    Map<SetData::Block>::Iterator i( d->b );
    while ( i ) {
        SetData::Block * b = i;
        ++i;
        if ( !b->count )
            b->recount();
        if ( !b->count )
            d->b.remove( b->start );
    }
}


/*! Returns true if this set contains all values in \a other, and
    false if not.
*/

bool IntegerSet::contains( const IntegerSet & other ) const
{
    Map<SetData::Block>::Iterator m( d->b );
    Map<SetData::Block>::Iterator h( other.d->b );
    while ( h ) {
        while ( m && m->start < h->start )
            ++m;
        if ( !m )
            return false;
        if ( h->start < m->start )
            return false;
        if ( h->count && m->count && h->count > m->count )
            return false;
        uint i = 0;
        while ( i < ArraySize ) {
            if ( ( m->contents[i] & h->contents[i] ) != h->contents[i] )
                return false;
            i++;
        }
        ++h;
    }
    return true;
}
