#include "create.h"

#include "mailbox.h"


/*! \class Create create.h
    Creates a new mailbox (RFC 3501, §6.3.3)
*/


/*! \reimp */

void Create::parse()
{
    space();
    name = astring();
    end();
}


/*! \reimp */

void Create::execute()
{
    if ( !m ) {
        m = new Mailbox( name, this );
        if ( name.lower() == "inbox" )
            m->setState( Mailbox::Failed );
    }

    if ( !m->done() )
        m->create();

    if ( !m->done() )
        return;
    
    if ( m->state() == Mailbox::Failed )
        error( No, "Couldn't create " + name );
    finish();
}
