#include "select.h"

#include "imap.h"
#include "mailbox.h"

static inline String fn( uint n ) { return String::fromNumber( n ); }


/*! \class Select select.h
    Opens a mailbox for read-write access (RFC 3501, §6.3.1)

    This class implements both Select and Examine. The constructor has
    to tell execute() what to do by setting the readOnly flag.
*/


/*! Creates a Select object to handle SELECT if \a ro if false, and to
    handle EXAMINE if \a ro is true.
*/

Select::Select( bool ro )
    : readOnly( ro ), m( 0 )
{
}


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
        m->setReadOnly( readOnly );
    }

    if ( !m->done() )
        m->select();

    if ( !m->done() )
        return;

    if ( m->state() == Mailbox::Failed ) {
        imap()->setMailbox( 0 );
        imap()->setState( IMAP::Authenticated );
        error( No, "Can't select " + name );
        finish();
        return;
    }

    imap()->setMailbox( m );
    imap()->setState( IMAP::Selected );

    respond( "FLAGS " + m->flags() );
    respond( fn( m->count() ) + " EXISTS" );
    respond( fn( m->recent() ) + " RECENT" );
    respond( "OK [UNSEEN " + fn( m->unseen() ) + "]" );
    respond( "OK [UIDNEXT " + fn( m->uidnext() ) + "]" );
    respond( "OK [UIDVALIDITY " + fn( m->uidvalidity() ) + "]" );
    respond( "OK [PERMANENTFLAGS " + m->permanentFlags() + "]" );
    respond( "OK [READ-" + String( m->readOnly() ? "ONLY" : "WRITE" ) + "]",
             Tagged );

    finish();
}


/*! Constructs an Examine handler, which is the same as a Select
    handler, except that it always is read-only.
*/

Examine::Examine()
    : Select( true )
{
}
