#include "select.h"

#include "imap.h"
#include "mailbox.h"


/*! \class Select select.h
    Opens a mailbox as specified in RFC 3501 section 6.3.1.

    This class also lends a helping hand to Examine. Normally, it
    attempts to get write access, but if it's working for Select it
    doesn't bother. In either case it reports whether the Mailbox is
    read-write or read-only.

    There may be a serious error here - what happens if we can't
    select? Should we leave the client in Authenticated or Selected
    state?
*/


/*! \fn Select::Select()

    Creates a command handler which, if \a readOnly is supplied and true,
    doesn't ask for write access.
*/



/*! \class Examine select.h
    Opens a mailbox as specified in RFC 3501 section 6.3.2.

    The actual work is done by Select; this class has no code of its own.
*/


/*! \fn Examine::Examine()

    Creates a command handler which calls Select while ensuring that
    Select won't ask for write access.
*/


/*! \reimp */

void Select::parse()
{
    space();
    m = astring();
    end();
}


/*! \reimp */

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
