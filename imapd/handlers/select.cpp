#include "select.h"

#include "imap.h"
#include "mailbox.h"
#include "messageset.h"
#include "imapsession.h"
#include "transaction.h"
#include "query.h"
#include "flag.h"


static inline String fn( uint n ) { return String::fromNumber( n ); }


class SelectData {
public:
    SelectData()
        : session( 0 ), m( 0 ), t( 0 ), recent( 0 )
    {}

    String name;
    bool readOnly;
    class ImapSession *session;
    Mailbox *m;

    Transaction *t;
    Query *recent;
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
    if ( !d->session ) {
        if ( imap()->session() )
            imap()->endSession();

        Mailbox *m = Mailbox::find( imap()->mailboxName( d->name ) );
        if ( !m || m->id() == 0 ) {
            error( No, "Can't select " + d->name );
            finish();
            return;
        }

        imap()->beginSession( m, d->readOnly );
        d->session = imap()->session();
        d->m = m;
    }

    if ( !d->t ) {
        // We select and delete the rows in recent_messages that refer
        // to our mailbox. Concurrent Selects of the same mailbox will
        // block until this transaction has committed.

        d->recent = new Query( "select * from recent_messages where "
                               "mailbox=$1 for update", this );
        d->recent->bind( 1, d->m->id() );

        Query *q = new Query( "delete from recent_messages where "
                              "mailbox=$1", this );
        q->bind( 1, d->m->id() );

        d->t = new Transaction( this );
        d->t->enqueue( d->recent );
        if ( !d->readOnly )
            d->t->enqueue( q );
        d->t->commit();
        return;
    }
    else {
        if ( !d->t->done() )
            return;

        while ( d->recent->hasResults() ) {
            Row *r = d->recent->nextRow();
            d->session->addRecent( r->getInt( "uid" ) );
        }
    }

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

    // ditto UNSEEN
    respond( "OK [UNSEEN 0]" );

    respond( "OK [UIDNEXT " + fn( d->m->uidnext() ) + "]" );
    respond( "OK [UIDVALIDITY " + fn( d->m->uidvalidity() ) + "]" );
    respond( "OK [PERMANENTFLAGS (" + flags +" \\*)]" );
    if ( d->session->readOnly() )
        respond( "OK [READ-ONLY]", Tagged );
    else
        respond( "OK [READ-WRITE]", Tagged );

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
