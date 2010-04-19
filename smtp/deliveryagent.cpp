// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "deliveryagent.h"

#include "spoolmanager.h"
#include "transaction.h"
#include "estringlist.h"
#include "smtpclient.h"
#include "recipient.h"
#include "injector.h"
#include "address.h"
#include "fetcher.h"
#include "message.h"
#include "graph.h"
#include "query.h"
#include "scope.h"
#include "timer.h"
#include "date.h"
#include "dsn.h"
#include "log.h"


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : messageId( 0 ), t( 0 ),
          qm( 0 ), qs( 0 ), qr( 0 ), message( 0 ), expired( false ),
          dsn( 0 ), injector( 0 ), update( 0 ), client( 0 ),
          updatedDelivery( false )
    {}

    uint messageId;
    Transaction * t;
    Query * qm;
    Query * qs;
    Query * qr;
    Message * message;
    uint deliveryId;
    bool expired;
    DSN * dsn;
    Injector * injector;
    Query * update;
    SmtpClient * client;
    bool updatedDelivery;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*! Creates a new DeliveryAgent object to deliver the message with the
    given \a id.
*/

DeliveryAgent::DeliveryAgent( uint id )
    : d( new DeliveryAgentData )
{
    setLog( new Log );
    Scope x( log() );
    log( "Attempting delivery for message " + fn( id ) );
    d->messageId = id;
}


/*! Returns the database ID of the message serviced, as specified to
    the constructor.
*/

uint DeliveryAgent::messageId() const
{
    return d->messageId;
}


void DeliveryAgent::execute()
{
    // Fetch and lock the row in deliveries matching (mailbox,uid).

    if ( !d->messageId )
        return;

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->qm = new Query(
            "select id, sender, current_timestamp > expires_at as expired "
            "from deliveries where message=$1 for update",
            this );
        d->qm->bind( 1, d->messageId );
        d->t->enqueue( d->qm );
        d->t->execute();
    }

    if ( !d->qm->done() )
        return;

    // Fetch other delivery data

    if ( d->qm->hasResults() ) {
        d->message = fetchMessage( d->messageId );

        Row * r = d->qm->nextRow();

        d->deliveryId = r->getInt( "id" );

        d->qs = new Query( "select localpart, domain from addresses "
                           "where id=$1", this );
        d->qs->bind( 1, r->getInt( "sender" ) );
        d->t->enqueue( d->qs );

        d->qr = new Query(
            "select recipient,localpart,domain,action,status,"
            "extract(epoch from last_attempt)::integer as last_attempt "
            "from delivery_recipients dr join addresses "
            "on (recipient=addresses.id) "
            "where delivery=$1 order by domain, localpart",
            this );
        d->qr->bind( 1, d->deliveryId );
        d->t->enqueue( d->qr );

        d->t->execute();

        if ( !r->isNull( "expired" ) && r->getBoolean( "expired" ) == true )
            d->expired = true;
    }
    else if ( !d->qs ) {
        d->t->rollback();
        d->messageId = 0;
        log( "Could not find/lock deliveries row; aborting" );
        return;
    }

    // When we have everything we need, we create a DSN for the message,
    // set the sender and recipients, then decide what to do.

    if ( !d->dsn ) {
        if ( !d->qs->done() || !d->qr->done() )
            return;

        if ( !( d->message->hasHeaders() &&
                d->message->hasAddresses() &&
                d->message->hasBodies() ) )
            return;

        createDSN();

        if ( !d->dsn->deliveriesPending() ) {
            d->t->rollback();
            d->messageId = 0;
            log( "Delivery already completed; will do nothing", Log::Debug );
            return;
        }
    }

    if ( !d->client && d->dsn->deliveriesPending() ) {
        d->client = SmtpClient::provide();
        d->client->send( d->dsn, this );
    }

    // Once the SmtpClient has updated the action and status for each
    // recipient, we can decide whether or not to spool a bounce.

    if ( !d->updatedDelivery ) {
        // Wait until there are no Unknown recipients.
        List<Recipient>::Iterator it( d->dsn->recipients() );
        while ( it && it->action() != Recipient::Unknown )
            ++it;
        if ( it )
            return;

        d->updatedDelivery = true;
        updateDelivery();

        if ( d->expired ) {
            log( "Delivery expired; will bounce", Log::Debug );
            expireRecipients( d->dsn );
        }

        if ( d->dsn->deliveriesPending() ) {
            // must try again
        }
        else if ( d->dsn->allOk() ) {
            // no need to tell anyone, right?
        }
        else {
            log( "Sending bounce message", Log::Debug );
            d->injector = injectBounce( d->dsn );
        }

        if ( d->injector )
            d->injector->execute();
    }

    // Once the update finishes, we're done.

    if ( !d->t->done() ) {
        d->t->commit();
        return;
    }

    if ( d->t->failed() && d->client && d->client->sent() ) {
        // We might end up resending copies of messages that we couldn't
        // update during this transaction.
        log( "Delivery attempt worked, but database could not be updated: " +
             d->t->error(), Log::Error );
        log( "Shutting down spool manager to avoid retransmissions.",
             Log::Error );
        SpoolManager::shutdown();
    }

    d->messageId = 0;
}


/*! Returns true if this DeliveryAgent is working on something, and
    false if not.
*/

bool DeliveryAgent::working() const
{
    if ( d->t && !d->t->done() )
        return true;
    return false;
}


/*! Begins to fetch a message with the given \a messageId, and returns a
    pointer to the newly-created Message object, which will be filled in
    by the message fetcher.
*/

Message * DeliveryAgent::fetchMessage( uint messageId )
{
    Message * m = new Message;
    m->setDatabaseId( messageId );
    Fetcher * f = new Fetcher( m, this );
    f->fetch( Fetcher::Addresses );
    f->fetch( Fetcher::OtherHeader );
    f->fetch( Fetcher::Body );
    f->setTransaction( d->t );
    f->execute();
    return m;
}


/*! Returns a pointer to a newly-created DSN for the DA's message,
    based on earlier queries. All queries are assumed to have
    completed successfully.
*/

void DeliveryAgent::createDSN()
{
    d->dsn = new DSN;
    d->dsn->setMessage( d->message );

    Row * r = d->qs->nextRow();
    Address * a = new Address( "", r->getEString( "localpart" ),
                               r->getEString( "domain" ) );
    d->dsn->setSender( a );

    if ( Configuration::hostname().endsWith( ".test.oryx.com" ) ) {
        // the sun never sets on the oryx empire. *sigh*
        Date * testTime = new Date;
        testTime->setUnixTime( 1181649536 );
        d->dsn->setResultDate( testTime );
    }

    while ( d->qr->hasResults() ) {
        r = d->qr->nextRow();

        Recipient * recipient = new Recipient;

        Address * a = new Address( "", r->getEString( "localpart" ),
                                   r->getEString( "domain" ) );
        a->setId( r->getInt( "recipient" ) );
        recipient->setFinalRecipient( a );

        Recipient::Action action =
            (Recipient::Action)r->getInt( "action" );
        if ( action == Recipient::Delayed )
            action = Recipient::Unknown;
        EString status;
        if ( !r->isNull( "status" ) )
            status = r->getEString( "status" );
        recipient->setAction( action, status );

        if ( !r->isNull( "last_attempt" ) ) {
            Date * date = new Date;
            date->setUnixTime( r->getInt( "last_attempt" ) );
            recipient->setLastAttempt( date );
        }

        d->dsn->addRecipient( recipient );
    }
}


/*! Updates all recipients for the given \a dsn to reflect that the
    message delivery request has expired.
*/

void DeliveryAgent::expireRecipients( DSN * dsn )
{
    List<Recipient>::Iterator it( dsn->recipients() );
    while ( it ) {
        Recipient * r = it;
        if ( r->action() == Recipient::Unknown ||
             r->action() == Recipient::Delayed )
            r->setAction( Recipient::Failed, "Expired" );
        ++it;
    }
}


/*! Logs a description of the delivery we are about to attempt, based on
    the specified \a dsn.
*/

void DeliveryAgent::logDelivery( DSN * dsn )
{
    uint total = dsn->recipients()->count();
    uint active = 0;
    EStringList l;

    List<Recipient>::Iterator it( dsn->recipients() );
    while ( it ) {
        Recipient * r = it;
        if ( r->action() == Recipient::Unknown ) {
            active++;
            Address * a = r->finalRecipient();
            l.append( a->lpdomain() );
        }
        ++it;
    }

    log( "Sending to " + l.join( ", " ) +
         " (" + fn( active ) + " of " + fn( total ) +
         " recipients)" );
}


/*! Returns a pointer to a newly-created Injector to inject a bounce
    message derived from the specified \a dsn, or 0 if the DSN was for
    a bounce already. The caller must call Injector::execute() when
    appropriate.
*/

Injector * DeliveryAgent::injectBounce( DSN * dsn )
{
    List<Address> * l = new List<Address>;
    if ( dsn->sender()->type() != Address::Normal )
        return 0;
    l->append( dsn->sender() );

    Injector * i = new Injector( this );
    i->setTransaction( d->t );
    i->addDelivery( dsn->result(), new Address( "", "", "" ), l );
    return i;
}


static GraphableCounter * messagesSent = 0;


/*! Updates the row in deliveries, as well as any related rows in
    delivery_recipients. The queries needed to perform the update are
    enqueued directly into d->t, for the caller to execute at will.
*/

void DeliveryAgent::updateDelivery()
{
    uint handled = 0;
    uint unhandled = 0;
    List<Recipient>::Iterator it( d->dsn->recipients() );
    while ( it ) {
        Recipient * r = it;
        ++it;
        if ( r->action() == Recipient::Unknown ||
             r->action() == Recipient::Delayed )
            unhandled++;
        else
            handled++;
        Query * q =
            new Query( "update delivery_recipients "
                       "set action=$1, status=$2, "
                       "last_attempt=current_timestamp "
                       "where delivery=$3 and recipient=$4",
                       this );
        q->bind( 1, (int)r->action() );
        q->bind( 2, r->status() );
        q->bind( 3, d->deliveryId );
        q->bind( 4, r->finalRecipient()->id() );
        if ( d->t->state() == Transaction::Executing )
            d->t->enqueue( q );
        else if ( r->action() == Recipient::Delivered ||
                  r->action() == Recipient::Relayed ||
                  r->action() == Recipient::Expanded )
            q->execute();
    }

    if ( d->dsn->allOk() ) {
        if ( handled )
            log( "Delivered message " + fn( d->messageId ) +
                 " successfully to " + fn( handled ) + " recipients",
                 Log::Significant );
        if ( !::messagesSent )
            ::messagesSent = new GraphableCounter( "messages-sent" );
        ::messagesSent->tick();
    }
    else {
        log( "Recipients handled: " + fn( handled ) +
             ", still queued: " + fn( unhandled ) );
    }
}
