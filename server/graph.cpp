// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "graph.h"

#include "allocator.h"
#include "eventloop.h"
#include "list.h"
#include "log.h"

#include <time.h> // time()


static List<GraphableNumber> * numbers = 0;


static const uint graphableHistorySize = 960; // 15 minutes and a little bit


class GraphableNumberData
    : public Garbage
{
public:
    GraphableNumberData(): min( 0 ), max( 0 ) {
        uint i = 0;
        while ( i < graphableHistorySize )
            values[i++] = 0;
    }
    String name;
    uint values[::graphableHistorySize];
    uint min;
    uint max;
};


/*! \class GraphableNumber graph.h

    The GraphableNumber class keeps track of past values of a number,
    and can compute averages for the recent past.

    When created, an object records itself by name, and there is a
    static function to obtain a list of all the objects.

    Objects of this class cannot be deleted. Once created, statistics
    are forever.
*/



/*!  Constructs a number called \a name. */

GraphableNumber::GraphableNumber( const String & name )
    : d( new GraphableNumberData )
{
    d->name = name;
    if ( !numbers ) {
        numbers = new List<GraphableNumber>;
        Allocator::addEternal( numbers, "numbers for statistics" );
    }
    numbers->append( this );
}


/*! This private helper gets rid of all expired history and makes sure
    that the maximum and minimum ends of the range encompass \a t.
*/

void GraphableNumber::clearOldHistory( uint t )
{
    if ( d->min < t - 2 * graphableHistorySize )
        d->min = t;
    while ( d->min < t + 1 - graphableHistorySize )
        d->values[d->min++%graphableHistorySize] = 0;
    if ( d->max < d->min )
        d->max = d->min;
    while ( d->max < t )
        d->values[(++d->max)%graphableHistorySize] =
            d->values[d->min%graphableHistorySize];
}


/*! Records the current value as \a v. The current time (with second
    resolution) is implicitly also recorded.
*/

void GraphableNumber::setValue( uint v )
{
    uint t = (uint)time( 0 );
    clearOldHistory( t );
    if ( v != d->values[t%graphableHistorySize] )
        log( "New value for " + d->name + ": " + fn( v ), Log::Debug );
    d->values[t%graphableHistorySize] = v;
}


/*! Returns the maximum value since time \a t. */

uint GraphableNumber::maximumSince( uint t ) const
{
    uint max = 0;
    if ( t < d->min )
        t = d->min;
    while ( t <= d->max ) {
        if ( d->values[t%graphableHistorySize] > max )
            max = d->values[t%graphableHistorySize];
        t++;
    }
    return max;
}


/*! Returns the minimum value since time \a t. */

uint GraphableNumber::minimumSince( uint t ) const
{
    uint min = UINT_MAX;
    if ( t < d->min )
        t = d->min;
    while ( t <= d->max ) {
        if ( d->values[t%graphableHistorySize] < min )
            min = d->values[t%graphableHistorySize];
        t++;
    }
    return min;
}


/*! Returns the average value since time \a t. Overflow is not handled. */

uint GraphableNumber::averageSince( uint t ) const
{
    uint s = 0;
    uint n = 0;
    if ( t < d->min )
        t = d->min;
    while ( t <= d->max ) {
        s += d->values[t%graphableHistorySize];
        n++;
        t++;
    }
    if ( !n )
        return 0;
    return (s + (n/2)) / n;

}


/*! Returns the most recent stored value. */

uint GraphableNumber::lastValue() const
{
    return d->values[d->max%graphableHistorySize];
}


/*! Returns the oldest time for which a value is recorded. */

uint GraphableNumber::oldestTime() const
{
    return d->min;
}


/*! Returns the youngest time for which a value is recorded. */

uint GraphableNumber::youngestTime() const
{
    return d->max;
}


/*! Returns the value at time \a t, or 0 if \a t is out of bounds. */

uint GraphableNumber::value( uint t )
{
    if ( t < d->min || t > d->max )
        return 0;
    return d->values[t%graphableHistorySize];
}


/*! Returns the name supplied to this object's constructor. */

String GraphableNumber::name() const
{
    return d->name;
}


/*! \class GraphableCounter graph.h
  
    The GraphableCounter class provides a tick counter; you can tell
    it to increase its value and look at its values in the past.
*/


/*! Constructs an empty counter and registers it as \a name. */

GraphableCounter::GraphableCounter( const String & name )
    : GraphableNumber( name )
{
}


/*! Increases the counter's value by 1. */

void GraphableCounter::tick()
{
    setValue( lastValue() + 1 );
}


class GraphableDataSetData
    : public Garbage
{
public:
    GraphableDataSetData(): t( 0 ), n( 0 ) {}
    uint t;
    uint s;
    uint n;
};


/*! \class GraphableDataSet graph.h
  
    The GraphableDataSet keeps track of numbers and keeps a record of
    their past averages.

    The current second is kept in some detail; past seconds are kept
    as averages only.
*/


/*! Constructs an empty data set named \a name. */

GraphableDataSet::GraphableDataSet( const String & name )
    : GraphableNumber( name )
{
}


/*! Adds \a n to this second's numbers. */

void GraphableDataSet::addNumber( uint n )
{
    uint now = (uint)time(0);
    if ( d->t < now ) {
        d->t = now;
        d->n = 0;
        d->s = 0;
    }
    n++;
    d->s += n;
    if ( d->n )
        setValue( ( d->s + (d->n/2) ) / d->n );
}


/*! \class GraphDumper graph.h
    This Connection subclass is responsible for transferring statistics
    en masse to any client that asks.
*/

/*! Dumps a frightful amount of data on the socket \a fd and closes it
    at once. The EventLoop will flush the data and make this object go
    away when it can.
*/

GraphDumper::GraphDumper( int fd )
    : Connection( fd, Connection::OryxServer )
{
    EventLoop::global()->addConnection( this );
    List<GraphableNumber>::Iterator i( numbers );
    String l;
    l.reserve( graphableHistorySize * 20 );
    while ( i ) {
        l.truncate();
        l.append( i->name() );
        if ( i->oldestTime() ) {
            uint t = i->oldestTime();
            while ( t <= i->youngestTime() ) {
                l.append( " " );
                l.append( fn( t ) );
                l.append( ":" );
                uint v = i->value( t );
                l.append( fn( v ) );
                t++;
                uint n = 0;
                while ( t < i->youngestTime() &&
                        v == i->value( t ) &&
                        n < 27 ) {
                    t++;
                    n++;
                }
            }
            l.append( "\r\n" );
            enqueue( l );
        }
        ++i;
    }
    setTimeoutAfter( 0 );
}


void GraphDumper::react( Event )
{
    setState( Closing );
}
