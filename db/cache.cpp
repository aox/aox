#include "cache.h"


/*! \class CacheLookup cache.h
    This class indicates the progress of a cache lookup operation.

    Each cache manager (e.g., AddressCache) has a "lookup()" method that
    returns a CacheLookup object, whose state() is set to Completed when
    the operation is complete.
*/

/*! Creates a CacheLookup object in the Executing state. */

CacheLookup::CacheLookup()
{
    st = Executing;
}


/*! Sets this object's state to \a s. */

void CacheLookup::setState( State s )
{
    st = s;
}


/*! Returns the state of this object. */

CacheLookup::State CacheLookup::state() const
{
    return st;
}


/*! Returns true only if the cache lookup operation has completed. */

bool CacheLookup::done() const
{
    return st == Completed;
}
