#include "select.h"

#include "imap.h"
#include "mailbox.h"
#include "imapsession.h"

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
    : readOnly( ro ), session( 0 )
{
}


/*! \class Examine select.h
    Opens a mailbox for read-only access (RFC 3501, §6.3.1)

    This class merely inherits from Select and sets the readOnly flag.
    It has no code of its own.
*/

/*! Constructs an Examine handler, which is the same as a Select
    handler, except that it always is read-only.
*/

Examine::Examine()
    : Select( true )
{
}


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
    if ( !session ) {
        if ( imap()->session() )
            imap()->endSession();
        imap()->beginSession( name, readOnly, this );
        session = imap()->session();
    }

    if ( !session->loaded() )
        return;

    if ( session->failed() ) {
        error( No, "Can't select " + name );
        finish();
        return;
    }

#if 0
    Mailbox *m = session->mailbox();

    respond( "FLAGS " + m->flags() );
    respond( fn( m->count() ) + " EXISTS" );
    respond( fn( m->recent() ) + " RECENT" );
    respond( "OK [UNSEEN " + fn( m->unseen() ) + "]" );
    respond( "OK [UIDNEXT " + fn( m->uidnext() ) + "]" );
    respond( "OK [UIDVALIDITY " + fn( m->uidvalidity() ) + "]" );
    respond( "OK [PERMANENTFLAGS " + m->permanentFlags() + "]" );
    respond( "OK [READ-" + String( m->readOnly() ? "ONLY" : "WRITE" ) + "]",
             Tagged );
#endif

    finish();
}
