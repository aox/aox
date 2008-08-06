// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "granter.h"

#include "query.h"
#include "transaction.h"


class GranterData
    : public Garbage
{
public:
    GranterData()
        : result( 0 ), t( 0 ), q( 0 )
    {}

    Query * result;
    String name;
    Transaction * t;
    Query * q;
};


/*! \class Granter granter.h
    Does the grant work for objects in the database.
*/

/*! Creates a new Granter to grant permissions to \a name within the
    Transaction \a t on behalf of \a owner, which will be notified
    when the Granter is done. */

Granter::Granter( const String & name, Transaction * t,
                  EventHandler * owner )
    : d( new GranterData )
{
    d->result = new Query( owner );
    d->name = name;
    d->t = t;
}


/*! Returns a pointer to a Query object that can be used to track the
    progress of this Granter. */

Query * Granter::result()
{
    return d->result;
}


void Granter::execute()
{
    d->result->setState( Query::Completed );
}
