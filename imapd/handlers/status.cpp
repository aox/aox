#include "status.h"


/*! \class Status status.h
    Returns the status of the specified mailbox (RFC 3501, §6.3.10)
*/


/*! \reimp */

void Status::parse()
{
    space();
    mailbox = astring();
    space();
    require( "(" );

    while ( 1 ) {
        String item = letters( 1, 11 ).lower();

        if ( item == "messages" )
            messages = true;
        else if ( item == "recent" )
            recent = true;
        else if ( item == "uidnext" )
            uidnext = true;
        else if ( item == "uidvalidity" )
            uidvalidity = true;
        else if ( item == "unseen" )
            unseen = true;
        else
            error( Bad, "Unknown STATUS item " + item );

        if ( nextChar() == ' ' )
            space();
        else
            break;
    }

    require( ")" );
    end();
}


/*! \reimp */

void Status::execute()
{
    finish();
}
