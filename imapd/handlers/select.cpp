#include "select.h"

#include "../imap.h"
#include "../mailbox.h"

void Select::parse()
{
    m = astring();
    end();
}

void Select::execute()
{
    Mailbox *mbox = new Mailbox( m );

    if ( readOnly )
        mbox->setReadOnly( true );
    
    if (mbox->load()) {
        imap()->setMailbox( mbox );
        imap()->setState( IMAP::Selected );
    }
    else {
        imap()->setMailbox( 0 );
        imap()->setState( IMAP::Authenticated );
        error( No, "Can't select mailbox " + m );
    }

    // Send mailbox data here.
    respond( "OK" );
    setState( Finished );
}
