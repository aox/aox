#include "select.h"

#include "imap.h"
#include "mailbox.h"
#include "messageset.h"
#include "imapsession.h"
#include "transaction.h"
#include "query.h"
#include "flag.h"
#include "message.h"


class SelectData {
public:
    SelectData()
        : mailbox( 0 ), session( 0 ), setup( 0 ),
          t( 0 ), recent( 0 ), messages( 0 )
    {}

    String name;
    bool readOnly;
    Mailbox * mailbox;
    ImapSession *session;
    ImapSessionInitializer * setup;

    Transaction * t;
    Query * recent;
    Query * messages;
};


/*! \class Select select.h
    Opens a mailbox for read-write access (RFC 3501, §6.3.1)

    This class implements both Select and Examine. The constructor has
    to tell execute() what to do by setting the readOnly flag.
*/

/*! Creates a Select object to handle SELECT if \a ro if false, and to
    handle EXAMINE if \a ro is true.
*/

Select::Select( bool ro )
    : d( new SelectData )
{
    d->readOnly = ro;
}


/*! \reimp */

void Select::parse()
{
    space();
    d->name = astring();
    end();
}


/*! \reimp */

void Select::execute()
{
    if ( !d->mailbox ) {
        d->mailbox = Mailbox::find( imap()->mailboxName( d->name ) );
        if ( !d->mailbox )
            error( No, d->name + " does not exist" );
        else if ( d->mailbox->synthetic() )
            error( No, d->name + " is not in the database" );
        else if ( d->mailbox->deleted() )
            error( No, d->name + " is deleted" );
        if ( !ok() ) {
            finish();
            return;
        }
    }
    if ( !d->setup ) {
        // this should expunge, shouldn't it? how? think later
        if ( imap()->session() )
            imap()->endSession();
        d->session = new ImapSession( d->mailbox, imap(), d->readOnly );
        d->setup = new ImapSessionInitializer( d->session, this );
    }

    if ( !d->setup->done() )
        return;

    String flags = "\\Answered \\Flagged \\Deleted \\Seen \\Draft";
    const List<Flag> * l = Flag::flags();
    List<Flag>::Iterator i( l->first() );
    while ( i ) {
        flags = flags + " " + i->name();
        i++;
    }

    respond( "FLAGS (" + flags + ")" );

    respond( fn( d->session->count() ) + " EXISTS" );
    respond( fn( d->session->recent().count() ) + " RECENT" );

    uint unseen = 0;
    Message * m = 0;
    // fetch a message
    while ( m ) {
        if ( !m->flag( Message::SeenFlag ) )
            unseen++;
        // next message
    }

    respond( "OK [UNSEEN " + fn( unseen ) + "]" );

    respond( "OK [UIDNEXT " + fn( d->mailbox->uidnext() ) + "]" );
    respond( "OK [UIDVALIDITY " + fn( d->mailbox->uidvalidity() ) + "]" );
    respond( "OK [PERMANENTFLAGS (" + flags +" \\*)]" );
    if ( d->session->readOnly() )
        respond( "OK [READ-ONLY]", Tagged );
    else
        respond( "OK [READ-WRITE]", Tagged );

    imap()->beginSession( d->session );
    finish();
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
