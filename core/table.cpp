// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "table.h"


class TableBaseData
{
public:
    TableBaseData() : numWanted( 0 ) {}

    uint wanted[1024];
    uint numWanted;
};


/*! \class TableBase table.h
  TableBase is a helper class for the Table template.

  Table, in order to be small and fully inline, puts some functions in
  an inherited base class: TableBase.

  TableBase is responsible for doing anything which Table needs done
  and which doesn't fit in a small inline function in table.h.
*/


/*! \class Table table.h
  Table is a template class mapping integers to pointers.

  Table can conveniently map integers, such as those used as unique
  keys in a database, to pointers to objects, such as those used in a
  cache, and automatically remembers lookup misses.

  It can also provide a list of the lookup failures().
*/


/*! \fn Table::Table()
    Creates an empty Table.
*/


/*! Creates an empty TableBase */

TableBase::TableBase()
    : d( new TableBaseData )
{
}


/*! Deletes the TableBase, erasing all records. */

TableBase::~TableBase()
{
}


/*! Note that \a i has been searched for, but not found. The relevant
    database row will later be fetched from the database.

    The number of remembered items are capped at 1024. There should be
    a limit, but how high should it be? We don't want to send the
    server arbitrarily big queries. If the load becomes bad, we want
    to fail in a way which keeps the database working well.
*/

void TableBase::note( uint i )
{
    if ( d->numWanted >= 1024 )
        return;
    uint n = 0;
    while ( n < d->numWanted ) {
        if ( d->wanted[n] == i )
            return;
        n++;
    }
    d->wanted[d->numWanted] = i;
    d->numWanted++;
}



/*! Clears the list of logged failures. This may be used immediately
    after failures(), for example.
*/

void TableBase::clear()
{
    d->numWanted = 0;
}


/*! Returns a string describing the noted lookup failures since the
    last call to clear(). A limited number of failures are logged, to
    prevent this string from growing out of all proportion.
*/

String TableBase::failures()
{
    String s;
    uint i = 0;
    while ( i < d->numWanted ) {
        s = s +
            ( i > 0 ? " or " : "" ) +
            "id=" + fn( d->wanted[i] );
        i++;
    }
    return s;
}


