/*! \class Select select.h
    \brief Opens a mailbox (RFC 3501, §6.3.1)
*/

#include "select.h"

#include "imap.h"
#include "mailbox.h"

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

    if ( mbox->load() ) {
        imap()->setMailbox( mbox );
        imap()->setState( IMAP::Selected );
    }
    else {
        imap()->setMailbox( 0 );
        imap()->setState( IMAP::Authenticated );
        error( No, "Can't select mailbox " + m );
        return;
    }

    // Send mailbox data here.
    respond( "EXISTS " + String::fromNumber( mbox->count() ) );

    String ok = "OK [READ-";
    ok.append( readOnly ? "ONLY" : "WRITE" );
    ok.append( "]" );
    respond( ok, Tagged );

    setState( Finished );
}
