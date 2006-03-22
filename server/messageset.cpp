// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "messageset.h"

#include "string.h"
#include "list.h"


class SetData
    : public Garbage
{
public:
    SetData() {}

    struct Range
        : public Garbage
    {
        Range( uint s, uint l ): start( s ), length( l ) {}
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
    if ( d != other.d ) {
        delete d;
        d = new SetData;

        List< SetData::Range >::Iterator it( other.d->l );
        while ( it ) {
            SetData::Range *r = it;
            d->l.append( new SetData::Range( r->start, r->length ) );
            ++it;
        }
    }
    return *this;
}


/*! Adds all numbers between \a n1 and \a n2 to the set, including
    both \a n1 and \a n2.

    \a n1 and \a n2 must both be nonzero.
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

    List< SetData::Range >::Iterator i( d->l );

    while ( i && i->start < n1 )
        ++i;
    d->l.insert( i, new SetData::Range( n1, n2-n1+1 ) );
    if ( i )
        --i;
    else
        i = d->l.last();

    // step back once and merge twice, in order to merge the newly
    // inserted range with both of its neighbours.
    uint left = 2;
    if ( i == d->l.first() )
        left--;
    else
        --i;
    while ( left && i ) {
        List< SetData::Range >::Iterator j = i;
        ++j;

        if ( i && j && i->start + i->length >= j->start ) {
            uint last = j->start + j->length - 1;
            d->l.take( j );
            if ( last < i->start + i->length - 1 ) {
                left++;
                last = i->start + i->length - 1;
            }
            i->length = last + 1 - i->start;
        }
        else {
            ++i;
            left--;
        }
    }
}


/*! Adds each value in \a set to this set. */

void MessageSet::add( const MessageSet & set )
{
    List<SetData::Range>::Iterator it( set.d->l );
    while ( it ) {
        add( it->start, it->start + it->length - 1 );
        ++it;
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
    done (yet). The "WHERE" prefix is not included, only e.g "uid>3 and
    uid<77".

    If \a table is non-empty, all column references are qualified with
    its value (i.e., table.column).
*/

String MessageSet::where( const String & table ) const
{
    String n( "uid" );
    if ( !table.isEmpty() )
        n = table + ".uid";
    String s;
    s.reserve( 22*d->l.count() );

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
        if ( !s.isEmpty() )
            s.append( " or " );
        s.append( p );

        ++it;
    }
    // look at me! look at me! I optimize!
    if ( s.startsWith( "(" ) && s.endsWith( ")" ) &&
         !s.mid( 1 ).contains( "(" ) )
        // oooh! I remove the unnecessary parens!
        s = s.mid( 1, s.length()-2 );
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
    List<SetData::Range>::Iterator i( d->l );
    while ( i && i->start + i->length - 1 < value )
        ++i;
    if ( !i || i->start > value || i->start + i->length - 1 < value )
        return;

    // four possible cases: entire, first, middle and end.
    if ( value == i->start && i->length == 1 ) {
        // value is the entire range
        d->l.take( i );
    }
    else if ( value == i->start ) {
        // value is first in the range
        i->length = i->length - 1;
        i->start = i->start + 1;
    }
    else if ( value == i->start + i->length - 1 ) {
        // value is last in the range
        i->length = i->length - 1;
    }
    else {
        // value is in the middle somewhere
        uint last = i->start + i->length - 1;
        i->length = value - i->start;
        add( value+1, last );
    }
}


/*! Removes all values contained in \a other from this set. */

void MessageSet::remove( const MessageSet & other )
{
    List<SetData::Range>::Iterator mine( d->l );
    List<SetData::Range>::Iterator hers( other.d->l );
    while ( mine && hers ) {
        while ( hers && hers->start + hers->length <= mine->start )
            ++hers;
        if ( hers ) {
            // my start and end, her start and end
            uint ms = mine->start;
            uint me = mine->start + mine->length;
            uint hs = hers->start;
            uint he = hers->start + hers->length;
            if ( hs <= ms && he > ms && he < me ) {
                // she includes my first byte, but not all of me
                mine->start = he;
                mine->length = me - he;
            }
            else if ( he >= me && hs > ms ) {
                // she overlaps my last byte, but not all of me
                mine->length = hs - ms;
            }
            else if ( hs > ms && he < me ) {
                // she's within me: break myself in two
                mine->length = hs - ms;
                add( he, me-1 );
            }
            else if ( hs <= ms && he >= me ) {
                // she covers all of me
                List<SetData::Range>::Iterator r( mine );
                ++mine;
                d->l.take( r );
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
    List<SetData::Range>::Iterator me( d->l );
    List<SetData::Range>::Iterator her( other.d->l );
    MessageSet r;

    while ( me && her ) {
        uint b = me->start;
        if ( me->start < her->start )
            b = her->start;
        uint e = me->start + me->length - 1;
        if ( me->start + me->length > her->start + her->length )
            e = her->start + her->length - 1;
        if ( b <= e )
            r.add( b, e );
        if ( me->start + me->length <= e+1 )
            ++me;
        if ( her->start + her->length <= e+1 )
            ++her;
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

    At first glance, this function's performance is O(n*n) where n is
    the number of gaps. However, in practice almost every case is
    O(n), because the way index() is used in this function, index()
    tends to be O(1) instead of O(n).
*/

void MessageSet::addGapsFrom( const MessageSet & other )
{
    List< SetData::Range >::Iterator it( other.d->l );
    while ( it ) {
        uint last = it->start + it->length - 1;
        ++it;
        if ( it ) {
            uint i = index( last );
            if ( i && i+1 == index( it->start ) )
                add( last+1, it->start-1 );
        }
    }
}
