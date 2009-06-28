// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "spoolmanager.h"

#include "query.h"
#include "timer.h"
#include "mailbox.h"
#include "entropy.h"
#include "dbsignal.h"
#include "recipient.h"
#include "deliveryagent.h"
#include "configuration.h"
#include "integerset.h"
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
        : q( 0 ), t( 0 ), again( false )
    {}

    Query * q;
    Timer * t;
    List<DeliveryAgent> agents;
    bool again;
};


/*! \class SpoolManager spoolmanager.h
    This class periodically attempts to deliver mail from the special
    /archiveopteryx/spool mailbox to a smarthost using DeliveryAgent.
    Messages in the spool are marked for deletion when the delivery
    either succeeds, or is permanently abandoned.

    Each archiveopteryx process has only one instance of this class,
    which is created by SpoolManager::setup().
*/

SpoolManager::SpoolManager()
    : d( new SpoolManagerData )
{
    setLog( new Log );
}


void SpoolManager::execute()
{
    // Fetch a list of spooled messages, and the next time we can try
    // to deliver each of them.

    if ( !d->q ) {
        IntegerSet have;
        List<DeliveryAgent>::Iterator a( d->agents );
        while ( a ) {
            if ( a->done() ) {
                d->agents.take( a );
            }
            else {
                have.add( a->messageId() );
                ++a;
            }
        }

        log( "Starting queue run" );
        d->again = false;
        reset();
        EString s( "select d.message, "
                   "extract(epoch from"
                   " min(coalesce(dr.last_attempt+interval '900 s',"
                   " current_timestamp)))::bigint"
                   "-extract(epoch from current_timestamp)::bigint as delay "
                   "from deliveries d "
                   "join delivery_recipients dr on (d.id=dr.delivery) "
                   "where (dr.action=$1 or dr.action=$2) "
                   "and (d.deliver_after is null"
                   " or d.deliver_after<=current_timestamp) " );
        if ( !have.isEmpty() )
            s.append( "and not d.message=any($3) " );
        s.append( "group by d.message "
                  "order by delay" );
        d->q = new Query( s, this );
        d->q->bind( 1, Recipient::Unknown );
        d->q->bind( 2, Recipient::Delayed );
        if ( !have.isEmpty() )
            d->q->bind( 3, have );
        d->q->execute();
    }

    if ( d->q && !d->q->done() )
        return;

    // Is there anything we might do?

    if ( d->q && !d->q->rows() ) {
        // No. Just finish.
        reset();
        log( "Ending queue run" );
        return;
    }

    // Yes. What?

    if ( d->q ) {
        uint delay = UINT_MAX;
        while ( d->q->hasResults() ) {
            Row * r = d->q->nextRow();
            int64 deliverableAt = r->getBigint( "delay" );
            if ( deliverableAt <= 0 ) {
                DeliveryAgent * a
                    = new DeliveryAgent( r->getInt( "message" ), this );
                (void)new Timer( a, d->agents.count() );
                d->agents.append( a );
            }
            else if ( delay > deliverableAt )
                delay = deliverableAt;
        }
        if ( delay < UINT_MAX ) {
            log( "Will process the queue again in " +
                 fn( delay ) + " seconds" );
            d->t = new Timer( this, delay );
        }
        d->q = 0;
    }

    reset();
}


/*! This function is called whenever a new row is added to the
    deliveries table, and updates the state machine so the message
    will be delivered soon.
*/

void SpoolManager::deliverNewMessage()
{
    if ( d->q ) {
        d->again = true;
        log( "New message added to spool while spool is being processed",
             Log::Debug );
        return;
    }
    else if ( SmtpClient::request( this ) ) {
        log( "New message added to spool; SMTP connection available" );
        d->again = true;
        execute();
    }
    else {
        log( "New message added to spool; will deliver when possible" );
        d->again = true;
        reset();
    }
}



/*! Resets the perishable state of this SpoolManager, i.e. all but the
    Timer. Provided for convenience.
*/

void SpoolManager::reset()
{
    delete d->t;
    d->t = 0;
    if ( d->again )
        d->t = new Timer( this, 1 );
    d->q = 0;
}


class SpoolRunner
    : public EventHandler
{
public:
    SpoolRunner(): EventHandler() {}
    void execute() { if ( ::sm ) ::sm->deliverNewMessage(); }
};


/*! Creates a SpoolManager object and a timer to ensure that it's
    started once (after which it will ensure that it wakes up once
    in a while). This function expects to be called from ::main().
*/

void SpoolManager::setup()
{
    if ( ::sm )
        return;

    ::sm = new SpoolManager;
    Allocator::addEternal( ::sm, "spool manager" );
    Database::notifyWhenIdle( sm );
    (void)new DatabaseSignal( "deliveries_updated", new SpoolRunner );
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
           "Please contact info@aox.org", Log::Error );
}
