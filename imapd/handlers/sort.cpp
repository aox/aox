// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "sort.h"


class SortData
    : public Garbage
{
public:
    SortData()
        : uid( false )
    {}

    bool uid;
};


/*! \class Sort sort.h
    Implements the SORT extension described in draft-ietf-imapext-sort.
*/


/*! Creates a new handler for SORT (or UID SORT, if \a u is true). */

Sort::Sort( bool u )
    : d( new SortData )
{
    d->uid = u;
}


void Sort::parse()
{
    end();
}


void Sort::execute()
{
    finish();
}
