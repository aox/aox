// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "spoolmanager.h"

#include "query.h"
#include "timer.h"
#include "mailbox.h"
#include "entropy.h"
#include "recipient.h"
#include "deliveryagent.h"
#include "configuration.h"
#include "smtpclient.h"
#include "allocator.h"
#include "scope.h"


static SpoolManager * sm;
static bool shutdown;


class SpoolManagerData
    : public Garbage
{
public:
    SpoolManagerData()
        : nextRun( 0 ), q( 0 ), t( 0 ), row( 0 ), client( 0 ),
          agent( 0 ), uidnext( 0 ), retry( 1 ), log( 0 )
    {}

    Query * nextRun;
    Query * q;
    Timer * t;
    Row * row;
    SmtpClient * client;
    DeliveryAgent * agent;
    uint uidnext;
    uint retry;
    Log * log;
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
    d->log = new Log( Log::General );
}


void SpoolManager::execute()
{
    // Start a queue run only when the Timer wakes us
    if ( d->t && d->t->active() )
        return;

    Scope x( d->log );

    // Find the number of seconds until we need to retry any existing
    // recipient (which will be 0 if we have anything to do right now).

    if ( !d->nextRun ) {
        d->nextRun =
            new Query(
                "select coalesce("
                "(extract(epoch from current_timestamp)-"
                "extract(epoch from min(case "
                "when action=$2 then last_attempt+interval '600s' "
                "when action=$1 then current_timestamp end)))::int, "
                "600) as next_attempt from "
                "delivery_recipients where action=$1 or action=$2",
                this
            );
        d->nextRun->bind( 1, Recipient::Unknown );
        d->nextRun->bind( 2, Recipient::Delayed );
        d->nextRun->execute();
    }

    if ( !d->nextRun->done() )
        return;

    // Do we need to wake up yet?

    if ( !d->q ) {
        uint next;
        Row * r = d->nextRun->nextRow();
        if ( r )
            next = r->getInt( "next_attempt" );
        else
            next = 666;

        if ( d->nextRun->failed() || !r || next > 0 ) {
            log( "Ending queue run (sleeping for " + fn( next ) +
                 " seconds)" );
            if ( d->client )
                d->client->logout( 4 );
            reset();
            d->t = new Timer( this, next );
            return;
        }
    }

    // Fetch a list of spooled messages.

    if ( !d->q ) {
        log( "Starting queue run" );
        reset();
        d->q = new Query( "select distinct d.id, d.message from deliveries d "
                          "join delivery_recipients dr on (d.id=dr.delivery) "
                          "where dr.action=$1 or dr.action=$2",
                          this );
        d->q->bind( 1, Recipient::Unknown );
        d->q->bind( 2, Recipient::Delayed );
        d->q->execute();
    }

    // For each one, create and run a DeliveryAgent.
    while ( d->row || d->q->hasResults() ) {
        if ( !d->row )
            d->row = d->q->nextRow();

        if ( !d->agent ) {
            if ( !d->client ) {
                d->client = client();
            }
            else {
                switch ( d->client->state() ) {
                case Connection::Connecting:
                case Connection::Connected:
                    break;
                case Connection::Inactive:
                case Connection::Listening:
                case Connection::Invalid:
                case Connection::Closing:
                    log( "Discarding existing SMTP client", Log::Debug );
                    d->client = client();
                    break;
                }
            }

            if ( !d->client->error().isEmpty() ) {
                log( "Couldn't connect to smarthost. Will try again in " +
                     fn( d->retry ) + " seconds.",
                     Log::Significant );
                d->client = 0;
                reset();
                d->t = new Timer( this, d->retry );
                d->retry = d->retry * 2;
                if ( d->retry > 300 )
                    d->retry = 300;
                return;
            }

            if ( !d->client->ready() )
                return;

            d->agent =
                new DeliveryAgent( d->client, d->row->getInt( "message" ),
                                   this );
            d->agent->execute();
        }

        if ( d->agent ) {
            if ( !d->agent->done() )
                return;
            d->retry = 1;
        }

        d->row = 0;
        d->agent = 0;
    }

    if ( !d->q->done() )
        return;

    reset();
    d->t = new Timer( this, 0 );
}


/*! Returns a pointer to a new SmtpClient to talk to the smarthost. */

SmtpClient * SpoolManager::client()
{
    Endpoint e( Configuration::text( Configuration::SmartHostAddress ),
                Configuration::scalar( Configuration::SmartHostPort ) );
    return new SmtpClient( e, this );
}


/*! Resets the perishable state of this SpoolManager, i.e. all but the
    Timer and the SmtpClient. Provided for convenience.
*/

void SpoolManager::reset()
{
    delete d->t;
    d->t = 0;
    d->q = 0;
    d->row = 0;
    d->agent = 0;
    d->nextRun = 0;
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
    if ( !::sm ) {
        ::sm = new SpoolManager;
        Allocator::addEternal( ::sm, "spool manager" );
    }
    if ( ::sm->d->t ) {
        Scope x( ::sm->d->log );
        ::sm->log( "Forcing immediate queue run", Log::Debug );
        ::sm->reset();
    }
    ::sm->execute();
}


/*! Creates a SpoolManager object and a timer to ensure that it's
    started once (after which it will ensure that it wakes up once
    in a while). This function expects to be called from ::main().
*/

void SpoolManager::setup()
{
    if ( !::sm ) {
        ::sm = new SpoolManager;
        Allocator::addEternal( ::sm, "spool manager" );
    }
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
