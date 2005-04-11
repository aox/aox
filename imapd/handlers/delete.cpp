// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "delete.h"

#include "imap.h"
#include "query.h"
#include "mailbox.h"


/*! \class Delete delete.h
    Deletes an existing mailbox (RFC 3501, §6.3.4)

    (Really deletes? What happens to the mail there?)
*/

Delete::Delete()
    : q( 0 )
{
}


void Delete::parse()
{
    space();
    name = astring();
    end();
}


void Delete::execute()
{
    if ( !q ) {
        Mailbox *m = Mailbox::find( imap()->mailboxName( name ) );
        if ( m && name.lower() != "inbox" ) {
            q = new Query( "update mailboxes set deleted=1 where id=$1", this );
            q->bind( 1, m->id() );
            q->execute();
        }
    }

    if ( q && !q->done() )
        return;

    if ( !q || q->failed() ) {
        error( No, "Couldn't delete " + name );
        finish();
        return;
    }

    // We need to inform the OCServer about what we did.

    finish();
}
