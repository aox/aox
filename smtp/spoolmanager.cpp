// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "spoolmanager.h"

#include "query.h"
#include "timer.h"
#include "mailbox.h"
#include "deliveryagent.h"


static SpoolManager * sm;
static bool shutdown;


class SpoolManagerData
    : public Garbage
{
public:
    SpoolManagerData()
        : q( 0 ), remove( 0 ), t( 0 ), row( 0 ), agent( 0 )
    {}

    Query * q;
    Query * remove;
    Timer * t;
    Row * row;
    DeliveryAgent * agent;
};


/*! \class SpoolManager spoolmanager.h
    This class periodically attempts to deliver mail from the special
    /archiveopteryx/spool mailbox to a smarthost using DeliveryAgent.
    Messages in the spool are marked for deletion when the delivery
    either succeeds, or is permanently abandoned.

    Each archiveopteryx process has only one instance of this class,
    which is created the first time SpoolManager::run() is called.
*/

SpoolManager::SpoolManager()
    : d( new SpoolManagerData )
{
}


void SpoolManager::execute()
{
    // Fetch a list of spooled messages.
    if ( !d->q ) {
        if ( d->t )
            delete d->t;
        d->t = 0;
        d->q =
            new Query( "select distinct mailbox,uid "
                       "from deliveries d left join deleted_messages dm "
                       "using (mailbox,uid) where dm.uid is null", this );
        d->q->execute();
    }

    // For each one, create and run a DeliveryAgent; and if it completes
    // its delivery attempt, delete the spooled message.
    while ( d->row || d->q->hasResults() ) {
        if ( !d->row )
            d->row = d->q->nextRow();

        if ( !d->agent ) {
            Mailbox * m = Mailbox::find( d->row->getInt( "mailbox" ) );
            // XXX: Is this test really necessary?
            if ( m ) {
                d->agent =
                    new DeliveryAgent( m, d->row->getInt( "uid" ), this );
                d->agent->execute();
            }
        }

        if ( d->agent ) {
            if ( !d->agent->done() )
                return;

            if ( !d->remove && d->agent->delivered() ) {
                d->remove =
                    new Query( "insert into deleted_messages "
                               "(mailbox, uid, deleted_by, reason) "
                               "values ($1, $2, null, $3)", this );
                d->remove->bind( 1, d->row->getInt( "mailbox" ) );
                d->remove->bind( 2, d->row->getInt( "uid" ) );
                d->remove->bind( 3, "Smarthost delivery " +
                                 d->agent->log()->id() );
                d->remove->execute();
            }

            if ( d->remove && !d->remove->done() )
                return;
        }

        d->row = 0;
    }

    if ( !d->q->done() )
        return;

    d->t = new Timer( this, 300 );
    d->q = 0;
}


/*! Causes the spool manager to re-examine the queue and attempt to make
    one or more deliveries, if possible.
*/

void SpoolManager::run()
{
    if ( ::shutdown ) {
        ::log( "Will not send spooled mail due to earlier database problem",
               Log::Error );
        return;
    }
    if ( !::sm )
        ::sm = new SpoolManager;
    ::sm->execute();
}


/*! Creates a SpoolManager object and a timer to ensure that it's
    started once (after which it will ensure that it wakes up once
    in a while). This function expects to be called from ::main().
*/

void SpoolManager::setup()
{
    if ( !::sm )
        ::sm = new SpoolManager;
    sm->d->t = new Timer( sm, 60 );
}


/*! Causes the spool manager to stop sending mail, at once. Should
    only be called if we're unable to update a message's "sent" status
    from "unsent" to "sent" and a loop threatens.
*/

void SpoolManager::shutdown()
{
    if ( ::sm && sm->d->t ) {
        delete sm->d->t;
        sm->d->t = 0;
    }
    ::sm = 0;
    ::shutdown = true;
    ::log( "Shutting down outgoing mail due to software problem. "
           "Please contact info@oryx.com", Log::Error );
}
