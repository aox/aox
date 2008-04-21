// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "messageset.h"

#include "stringlist.h"


class SetData
    : public Garbage
{
public:
    SetData() {}

    struct Range
        : public Garbage
    {
        Range( uint s, uint l ): start( s ), length( l ) {
            setFirstNonPointer( &start );
        }
        uint start;
        uint length;
    };

    List<Range> l;
};


/*! \class MessageSet messageset.h
    This class contains an IMAP message set.

    A MessageSet is just a set of nonnegative integers. It can add new
    members to the set, find its members by value() or index() (sorted
    by size, with 1 first), look for the largest contained number, and
    produce an SQL "where" clause matching its contents.
*/


/*! Constructs an empty set. */

MessageSet::MessageSet()
{
    d = new SetData;
}


/*! Constructs a set that's an exact copy of \a other. This
    constructor is a little expensive, both in time and space.
*/

MessageSet::MessageSet( const MessageSet & other )
    : Garbage()
{
    d = 0;
    *this = other;
}


MessageSet& MessageSet::operator=( const MessageSet & other )
{
    if ( d == other.d )
        return *this;

    d = new SetData;
    List< SetData::Range >::Iterator it( other.d->l );
    while ( it ) {
        d->l.append( new SetData::Range( it->start, it->length ) );
        ++it;
    }
    return *this;
}


/*! Adds all numbers between \a n1 and \a n2 to the set, including
    both \a n1 and \a n2.

    \a n1 and \a n2 must both be nonzero.

    f \a n1 and \a n2 are large, this function tends towards O(n)
    behaviour.  If the smallest of \a n1 and \a n2 is small, it tends
    towards O(1).  For this reason, it's better to add ranges to a
    MessageSet largest-first than smallest-first.
*/

void MessageSet::add( uint n1, uint n2 )
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

    List< SetData::Range >::Iterator i;
    if ( d->l.lastElement() && d->l.lastElement()->start <= n1 )
        i = d->l.last();
    else
        i = d->l.first();
    
    // skip all ranges that are separated from [n1,n2] by at least one
    // number, ie. whose last member is at most n1-2.

    while ( i && i->start + i->length - 1 < n1 - 1 )
        ++i;

    // if we're looking at a range now, it either overlaps with, is
    // adjacent to, or is after [n1,n2].
    
    if ( !i ) {
        // we're looking at the end
        d->l.append( new SetData::Range( n1, n2-n1+1 ) );
        i = d->l.last();
    }
    else if ( i->start - 1 > n2 ) {
        // it's after, not even touching
        d->l.insert( i, new SetData::Range( n1, n2-n1+1 ) );
        --i;
    }
    else {
        // it touches or overlaps
        uint s1 = n1;
        uint s2 = n2;
        if ( i->start < s1 )
            s1 = i->start;
        if ( i->start + i->length - 1 > s2 )
            s2 = i->start + i->length - 1;
        i->start = s1;
        i->length = s2 + 1 - s1;
    }

    // the following ranges may touch or overlap this one.
    bool touching = true;
    while ( touching ) {
        List<SetData::Range>::Iterator n( i );
        ++n;
        if ( !n || n->start > i->start + i->length ) {
            touching = false;
        }
        else {
            if ( n->start + n->length > i->start + i->length )
                i->length = n->start + n->length - i->start;
            d->l.take( n );
        }
    };
}


/*! Adds each value in \a set to this set. */

void MessageSet::add( const MessageSet & set )
{
    if ( isEmpty() ) {
        *this = set;
        return;
    }
    List<SetData::Range>::Iterator it( set.d->l.last() );
    while ( it ) {
        add( it->start, it->start + it->length - 1 );
        --it;
    }
    // oh. a simple one.
}


/*! Returns the smallest UID in this MessageSet, or 0 if the set is
    empty.
*/

uint MessageSet::smallest() const
{
    SetData::Range * r = d->l.first();
    if ( !r )
        return 0;
    return r->start;
}


/*! Returns the largest number in this MessageSet, or 0 if the set is
    empty.
*/

uint MessageSet::largest() const
{
    SetData::Range * r = d->l.last();
    if ( !r )
        return 0;
    return r->start + r->length - 1;
}


/*! Returns true if this set is a simple range, and 0 if it's more
    complex. (One-member sets are necessarily always ranges.)
*/

bool MessageSet::isRange() const
{
    if ( d->l.count() == 1 )
        return true;
    return false;
}


/*! Returns the number of numbers in this MessageSet. */

uint MessageSet::count() const
{
    uint c = 0;
    List<SetData::Range>::Iterator i( d->l );
    while ( i ) {
        c += i->length;
        ++i;
    }
    return c;
}


/*! Returns true if the set is empty, and false if not. */

bool MessageSet::isEmpty() const
{
    return d->l.isEmpty();
}


/*! Returns the value at \a index, or 0 if \a index is count() or
    greater.

    If this set contains the UIDs in a mailbox, this function converts
    from MSNs to UIDs. See Session::uid().
*/

uint MessageSet::value( uint index ) const
{
    uint c = 1;
    List<SetData::Range>::Iterator i( d->l );
    while ( i && c + i->length <= index ) {
        c += i->length;
        ++i;
    }
    if ( i && c <= index && c + i->length > index )
        return i->start + index - c;
    return 0;
}


/*! Returns the index of \a value index, or 0 if \a value is not in
    this Set.

    If this set contains the UIDs in a mailbox, this function converts
    from UIDs to MSNs. See Session::msn().
*/

uint MessageSet::index( uint value ) const
{
    uint c = 0;
    List<SetData::Range>::Iterator i( d->l );
    while ( i && i->start + i->length - 1 < value ) {
        c += i->length;
        ++i;
    }
    if ( i && i->start <= value && i->start + i->length - 1 >= value )
        return 1 + c + value - i->start;
    return 0;

}


/*! Returns an SQL WHERE clause describing the set. No optimization is
    done (yet). The "WHERE" prefix is not included, only e.g "uid>3"
    or "(uid>3 and uid<77)". The result contains enough parentheses to
    be suitable for use with boolean logic directly.

    If \a table is non-empty, all column references are qualified with
    its value (i.e., table.column). \a table should not contain a
    trailing dot.
*/

String MessageSet::where( const String & table ) const
{
    if ( isEmpty() )
        return "";

    String n( "uid" );
    if ( !table.isEmpty() )
        n = table + ".uid";
    StringList cl;

    List< SetData::Range >::Iterator it( d->l );
    while ( it ) {
        SetData::Range *r = it;
        String p;

        // we're missing the case where the set goes up to *, and the
        // case where two ranges can be merged due to holes.
        if ( r->length == 1 ) {
            p = n + "=" + fn( r->start );
        }
        else if ( r->start + r->length < r->start ) {
            // integer wraparound.
            p = n + ">=" + fn( r->start );
        }
        else if ( r->start == 1 ) {
            p = n + "<" + fn( 1+r->length );
        }
        else {
            p = "(" + n + ">=" + fn( r->start ) + " and " +
                n + "<" + fn( r->start + r->length ) + ")";
        }
        cl.append( p );

        ++it;
    }
    if ( cl.count() == 1 )
        return *cl.firstElement();
    String s;
    s.append( "(" );
    s.append( cl.join( " or " ) );
    s.append( ")" );
    return s;
}


/*! Returns true if \a value is present in this set, and false if not. */

bool MessageSet::contains( uint value ) const
{
    return index( value ) > 0;
}


/*! Removes \a value from this set. Does nothing unless \a value is
    present in the set.*/

void MessageSet::remove( uint value )
{
    MessageSet r;
    r.add( value, value );
    remove( r );
}


/*! Removes all values contained in \a other from this set. */

void MessageSet::remove( const MessageSet & other )
{
    List<SetData::Range>::Iterator mine( d->l );
    List<SetData::Range>::Iterator hers( other.d->l );
    while ( mine && hers ) {
        while ( hers && hers->start + hers->length - 1 < mine->start )
            ++hers;
        if ( hers ) {
            // my start and end, her start and end
            uint ms = mine->start;
            uint me = mine->start + mine->length - 1;
            uint hs = hers->start;
            uint he = hers->start + hers->length - 1;
            if ( hs <= ms && he >= ms && he < me ) {
                // she includes my first byte, but not all of me
                mine->start = he + 1;
                mine->length = me + 1 - mine->start;
            }
            else if ( he >= me && hs > ms && hs <= me ) {
                // she overlaps my last byte, but not all of me
                mine->length = hs - ms;
            }
            else if ( hs > ms && he < me ) {
                // she's within me: break myself in two
                mine->length = hs - ms;
                add( he+1, me );
            }
            else if ( hs <= ms && he >= me ) {
                // she covers all of me
                d->l.take( mine ); // steps mine to next
            }
        }
        if ( hers && mine && mine->start + mine->length <= hers->start )
            ++mine;
    }
}


/*! Returns a set containing all values which are contained in both
    this MessageSet and in \a other. */

MessageSet MessageSet::intersection( const MessageSet & other ) const
{
    List<SetData::Range>::Iterator me( d->l.last() );
    List<SetData::Range>::Iterator her( other.d->l.last() );
    MessageSet r;

    while ( me && her ) {
        uint b = me->start;
        if ( me->start < her->start )
            b = her->start;
        uint e = me->start + me->length - 1;
        if ( e > her->start + her->length - 1 )
            e = her->start + her->length - 1;
        if ( b <= e )
            r.add( b, e );
        if ( me->start >= b )
            --me;
        if ( her->start >= b )
            --her;
    }
    return r;
}


/*! Removes all numbers from this set. */

void MessageSet::clear()
{
    d = new SetData;
}


/*! Returns the contents of this set in IMAP syntax. The shortest
    possible representation is returned, with strictly increasing
    values, without repetitions, with ":" and "," as necessary.

    If the set is empty, so is the returned string.
*/

String MessageSet::set() const
{
    String r;
    List< SetData::Range >::Iterator it( d->l );
    while ( it ) {
        if ( !r.isEmpty() )
            r.append( "," );
        r.append( fn( it->start ) );
        if ( it->length > 1 ) {
            r.append( ":" );
            r.append( fn( it->start + it->length - 1 ) );
        }
        ++it;
    }
    return r;
}


/*! Adds some gaps from \a other, such that this set is expanded to
    contain a small number of contiguous ranges.

    A gap is added to this set if no numbers in the gap are in \a
    other, and the numbers just above and below the gap are in this
    set.

    This function is slow if \a other contains many gaps.

    Note that it is not safe to use this function for writing to the
    database. The database may contain rows with UIDs that aren't in
    \a other. This is harmless if we use the result to fetch data
    (we'll get some data we don't need, and which we'll discard once
    we discover we have no MSN for it), but could be dangerous if we
    write.
*/

void MessageSet::addGapsFrom( const MessageSet & other )
{
    if ( other.isEmpty() )
        return;
    if ( isEmpty() || isRange() )
        return;

    if ( other.smallest() > 1 && contains( other.smallest() ) )
        add( 1, other.smallest() - 1 );
    
    List<SetData::Range>::Iterator i( other.d->l );
    while ( i ) {
        uint before = i->start + i->length - 1;
        ++i;
        if ( i ) {
            uint after = i->start;
            if ( contains( before ) && contains( after ) )
                add( before+1, after-1 );
        }
    }

    if ( other.largest() < UINT_MAX && contains( other.largest() ) )
        add( other.largest() + 1, UINT_MAX );
}
