#include "select.h"

#include "imap.h"
#include "mailbox.h"

/*! \class Select select.h
    Opens a mailbox for read-write access (RFC 3501, §6.3.1)

    This class implements both Select and Examine. The constructor has
    to tell execute() what to do by setting the readOnly flag.
*/


/*! \class Examine select.h
    Opens a mailbox for read-only access (RFC 3501, §6.3.1)

    This class merely inherits from Select and sets the readOnly flag.
    It has no code of its own.
*/


/*! \reimp */

void Select::parse()
{
    space();
    name = astring();
    end();
}


/*! \reimp */

void Select::execute()
{
    if ( !m ) {
        m = new Mailbox( name, this );
        if ( readOnly )
            m->setReadOnly( true );
    }

    if ( !m->done() )
        m->load();

    if ( !m->done() )
        return;

    if ( m->state() == Mailbox::Failed ) {
        imap()->setMailbox( 0 );
        imap()->setState( IMAP::Authenticated );
        error( No, "Can't select mailbox " + name );
        return;
    }

    imap()->setMailbox( m );
    imap()->setState( IMAP::Selected );

    // Send mailbox data here.
    respond( "EXISTS " + String::fromNumber( m->count() ) );

    String ok = "OK [READ-";
    ok.append( readOnly ? "ONLY" : "WRITE" );
    ok.append( "]" );
    respond( ok, Tagged );

    finish();
}
