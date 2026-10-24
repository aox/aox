// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "copy.h"

#include "imapsession.h"
#include "transaction.h"
#include "integerset.h"
#include "mailbox.h"
#include "mover.h"
#include "query.h"
#include "user.h"


class CopyData
    : public Garbage
{
public:
    CopyData() :
        uid( false ), move( false ), committed( false ),
        read( false ), announced( false ),
        mailbox( 0 ),
        mover( 0 )
    {}
    bool uid;
    bool move;
    bool committed;
    bool read;
    bool announced;
    IntegerSet set;
    EString copyuid;
    Mailbox * mailbox;
    Mover * mover;
};


/*! \class Copy copy.h

    The Copy class implements the IMAP COPY command (RFC 3501 section
    6.4.7), as extended by RFC 4315.

    Copy copies all elements of a message, including such things as
    flags.
*/


/*! Constructs a Copy object parsing uids if \a uid is true, and msns
    if \a uid is false.
*/

Copy::Copy( bool uid )
    : Command(), d( new CopyData )
{
    d->uid = uid;
}


/*! Tells the Copy handler to expunge the messages after copying, in
    effect turning Copy into Move.

*/

void Copy::setMove()
{
    d->move = true;
}


void Copy::parse()
{
    space();
    d->set = set( !d->uid );
    shrink( &d->set );
    space();
    d->mailbox = mailbox();
    end();

    if ( !ok() )
        return;

    requireRight( d->mailbox, Permissions::Insert );
    requireRight( d->mailbox, Permissions::Write );
    if ( d->move ) {
        requireRight( session()->mailbox(), Permissions::Expunge );
        requireRight( session()->mailbox(), Permissions::DeleteMessages );
    }

    log( "Will copy " + fn( d->set.count() ) +
         " messages to " + d->mailbox->name().ascii() );
}


void Copy::execute()
{
    if ( state() != Executing )
        return;

    if ( d->set.isEmpty() ) {
        finish();
        return;
    }

    if ( !permitted() )
        return;

    if ( !transaction() ) {
        setTransaction( new Transaction( this ) );
        d->mover = new Mover( transaction(), imap()->user(),
                              session()->mailbox(), d->mailbox,
                              d->set, 0, d->move );
    }

    if ( !d->mover->done() )
        return;

    Query * report = d->mover->report();

    if ( !d->read && ( !report || report->done() ) ) {
        d->read = true;
        IntegerSet from;
        IntegerSet to;
        while ( report && report->hasResults() ) {
            Row * r = report->nextRow();
            from.add( r->getInt( "uid" ) );
            to.add( r->getInt( "nuid" ) );
        }
        if ( !from.isEmpty() )
            d->copyuid = "COPYUID " + fn( d->mailbox->uidvalidity() ) + " " +
                         from.set() + " " + to.set();
    }

    if ( d->move && !d->announced ) {
        // RFC9051 6.4.8 wants the client to hear about the copies
        // before it hears that the originals are gone, and the
        // session queues its expunges as soon as the refresh below
        // tells it about them, so this has to go out first - before
        // the commit, since that is what the session waits for.
        if ( !d->read )
            return;
        d->announced = true;
        if ( !d->copyuid.isEmpty() )
            respond( "OK [" + d->copyuid + "] moved" );
    }

    if ( !d->committed ) {
        d->committed = true;
        Mailbox::refreshMailboxes( transaction() );
        transaction()->commit();
    }

    if ( !transaction()->done() )
        return;

    if ( transaction()->failed() ) {
        error( No, "Database failure: " + transaction()->error() );
        return;
    }

    if ( imap() && imap()->session() &&
         imap()->session()->mailbox() == d->mailbox &&
         !imap()->session()->initialised() )
        return;

    if ( !d->announced ) {
        d->announced = true;
        // COPY keeps COPYUID in the tagged OK, as RFC4315 3 asks.
        if ( !d->copyuid.isEmpty() )
            setRespTextCode( d->copyuid );
    }

    finish();
}
