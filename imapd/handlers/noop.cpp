#include "noop.h"

#include "transaction.h"
#include "query.h"

/*! \class Noop noop.h
    NOOP does nothing (RFC 3501, §6.1.2)

    One might surmise that this function is a true noop, but it's not.
    The side effects need to be handled somehow.
*/

/*! \reimp */

Noop::Noop()
    : q1( 0 ), q2( 0 ), t( 0 )
{
}


/*! \reimp
    This has again become my pet testing ground. AMS 20040621
*/

void Noop::execute()
{
    if ( !t ) {
        t = new Transaction;
        q2 = new Query( "select currval('foo_id_seq')::integer as id", this );
        q1 = new Query( "insert into foo (bar) values ($1)", this );
        q1->bind( 1, "Foo" );
        t->enqueue( q1 );
        t->enqueue( q2 );
        t->end();
    }

    if ( !q2->done() )
        return;

    if ( !t->failed() ) {
        int n = *(q2->nextRow()->getInt( "id" ));
        respond( "OK " + String::fromNumber( n ) );
    }

    finish();
}



/*! \class Check noop.h
    Performs a checkpoint of the selected mailbox (RFC 3501, §6.4.1)

    This command needs to do nothing in our implementation.
*/

/*! \reimp */

void Check::execute()
{
    finish();
}
