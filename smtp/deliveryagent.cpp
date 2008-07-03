// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "deliveryagent.h"

#include "spoolmanager.h"
#include "transaction.h"
#include "stringlist.h"
#include "smtpclient.h"
#include "recipient.h"
#include "injector.h"
#include "address.h"
#include "fetcher.h"
#include "message.h"
#include "graph.h"
#include "query.h"
#include "scope.h"
#include "date.h"
#include "dsn.h"
#include "log.h"


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : log( 0 ), messageId( 0 ), owner( 0 ), t( 0 ),
          qm( 0 ), qs( 0 ), qr( 0 ), row( 0 ), message( 0 ),
          dsn( 0 ), injector( 0 ), update( 0 ), client( 0 ),
          delivered( false ), committed( false )
    {}

    Log * log;
    uint messageId;
    EventHandler * owner;
    Transaction * t;
    Query * qm;
    Query * qs;
    Query * qr;
    Row * row;
    Message * message;
    DSN * dsn;
    Injector * injector;
    Query * update;
    SmtpClient * client;
    bool delivered;
    bool committed;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*! Creates a new DeliveryAgent object to deliver the message with the
    given \a id using the specified SMTP \a client. The \a owner will
    be notified upon completion.
*/

DeliveryAgent::DeliveryAgent( SmtpClient * client, uint id,
                              EventHandler * owner )
    : d( new DeliveryAgentData )
{
    d->log = new Log( Log::SMTP );
    Scope x( d->log );
    log( "Attempting delivery for message #" + fn( id ) );
    d->client = client;
    d->messageId = id;
    d->owner = owner;
}


void DeliveryAgent::execute()
{
    Scope x( d->log );

    // Fetch and lock the row in deliveries matching (mailbox,uid).

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->qm = fetchDelivery( d->messageId );
        d->t->enqueue( d->qm );
        d->t->execute();
    }

    if ( !d->qm->done() )
        return;

    if ( d->qm->hasResults() ) {
        d->row = d->qm->nextRow();
        log( "Delivery ID is " + d->row->getInt( "id" ) );
    }

    if ( !d->messageId )
        return;

    // Fetch the sender address, the relevant delivery_recipients
    // entries, and the message itself. (If we're called again for
    // the same message after we've completed delivery, we'll do a
    // lot of work before realising that nothing needs to be done.)

    if ( !d->message && d->row ) {
        d->message = fetchMessage( d->messageId );

        d->qs = fetchSender( d->row->getInt( "sender" ) );
        d->t->enqueue( d->qs );

        d->qr = fetchRecipients( d->row->getInt( "id" ) );
        d->t->enqueue( d->qr );

        d->t->execute();
    }

    // When we have everything we need, we create a DSN for the message,
    // set the sender and recipients, then decide what to do.

    if ( !d->dsn && d->row ) {
        if ( !d->qs->done() || !d->qr->done() )
            return;

        if ( !( d->message->hasHeaders() &&
                d->message->hasAddresses() &&
                d->message->hasBodies() ) )
            return;

        d->dsn = createDSN( d->message, d->qs, d->qr );

        if ( d->dsn->deliveriesPending() ) {
            if ( !d->row->isNull( "expired" ) &&
                 d->row->getBoolean( "expired" ) == true )
            {
                log( "Delivery expired; will bounce", Log::Debug );
                expireRecipients( d->dsn );
            }
            else {
                logDelivery( d->dsn );
                d->client->send( d->dsn, this );
            }
        }
        else {
            log( "Delivery already completed; will do nothing", Log::Debug );
            d->delivered = true;
            d->row = 0;
        }
    }

    // Once the SmtpClient has updated the action and status for each
    // recipient, we can decide whether or not to spool a bounce.

    if ( !d->injector && !d->update && d->row ) {
        // Wait until there are no Unknown recipients.
        List<Recipient>::Iterator it( d->dsn->recipients() );
        while ( it && it->action() != Recipient::Unknown )
            ++it;

        if ( it )
            return;

        // Send a bounce message if all recipients have been handled,
        // and any of them failed.
        if ( !( d->dsn->deliveriesPending() ||
                d->dsn->allOk() ) )
        {
            log( "Sending bounce message", Log::Debug );
            d->injector = injectBounce( d->dsn );
        }

        if ( d->injector )
            d->injector->execute();
    }

    // Once we're done delivering (or bouncing) the message, we'll
    // update the relevant rows in delivery_recipients, so that we
    // know what to do next time around.

    if ( !d->update && d->row ) {
        if ( d->injector && !d->injector->done() )
            return;

        uint unhandled = updateDelivery( d->row->getInt( "id" ), d->dsn );
        if ( unhandled == 0 )
            d->delivered = true;

        d->t->execute();
    }

    // Once the update finishes, we're done.

    if ( !d->committed ) {
        if ( d->update && !d->update->done() )
            return;

        d->committed = true;
        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        // We might end up resending copies of messages that we couldn't
        // update during this transaction.
        log( "Delivery attempt failed due to database error: " +
             d->t->error(), Log::Error );
        log( "Shutting down spool manager.", Log::Error );
        SpoolManager::shutdown();
    }

    d->owner->execute();
}


/*! Returns true if this DeliveryAgent has finished processing
    deliveries for the message submitted to it.
*/

bool DeliveryAgent::done() const
{
    return d->t->done();
}


/*! Returns true if the message was delivered (or the delivery was
    permanently abandoned), and the spooled message may be deleted.
*/

bool DeliveryAgent::delivered() const
{
    return d->delivered;
}


/*! Returns a pointer to a Query that selects and locks the single row
    from deliveries that matches the given \a messageId.
*/

Query * DeliveryAgent::fetchDelivery( uint messageId )
{
    Query * q =
        new Query(
            "select id, sender, "
            "current_timestamp > expires_at as expired "
            "from deliveries "
            "where message=$1 and "
            "((tried_at is null or"
            "  tried_at+interval '1 hour' < current_timestamp)) "
            "for update", this );
    q->bind( 1, messageId );
    return q;
}


/*! Begins to fetch a message with the given \a messageId, and returns a
    pointer to the newly-created Message object, which will be filled in
    by the message fetcher.
*/

Message * DeliveryAgent::fetchMessage( uint messageId )
{
    MessageFetcher * f =
        new MessageFetcher( messageId, this );

    f->execute();
    return f->message();
}


/*! Returns a pointer to a Query to fetch the address information for a
    message sender with the given \a sender id.
*/

Query * DeliveryAgent::fetchSender( uint sender )
{
    Query * q =
        new Query( "select localpart,domain from addresses "
                   "where id=$1", this );
    q->bind( 1, sender );
    return q;
}


/*! Returns a pointer to a Query that will fetch rows for the given
    \a delivery id from delivery_recipients.
*/

Query * DeliveryAgent::fetchRecipients( uint delivery )
{
    Query * q =
        new Query(
            "select recipient,localpart,domain,action,status,"
            "extract(epoch from last_attempt)::integer as last_attempt "
            "from delivery_recipients dr join addresses "
            "on (recipient=addresses.id) "
            "where delivery=$1 order by dr.id", this
        );
    q->bind( 1, delivery );
    return q;
}


/*! Returns a pointer to a newly-created DSN for the given \a message.
    The sender is filled in from \a qs (from fetchSender()), while the
    recipients are filled in from \a qr (from fetchRecipients()). Both
    queries are assumed to have completed successfully.
*/

DSN * DeliveryAgent::createDSN( Message * message, Query * qs, Query * qr )
{
    DSN * dsn = new DSN;
    dsn->setMessage( message );

    Row * r = qs->nextRow();
    Address * a =
        new Address( "", r->getString( "localpart" ),
                     r->getString( "domain" ) );
    dsn->setSender( a );

    if ( Configuration::hostname().endsWith( ".test.oryx.com" ) ) {
        // the sun never sets on the oryx empire. *sigh*
        Date * testTime = new Date;
        testTime->setUnixTime( 1181649536 );
        dsn->setResultDate( testTime );
    }

    while ( qr->hasResults() ) {
        r = qr->nextRow();

        Recipient * recipient = new Recipient;

        Address * a =
            new Address( "", r->getString( "localpart" ),
                         r->getString( "domain" ) );
        a->setId( r->getInt( "recipient" ) );
        recipient->setFinalRecipient( a );

        Recipient::Action action =
            (Recipient::Action)r->getInt( "action" );
        if ( action == Recipient::Delayed )
            action = Recipient::Unknown;
        String status;
        if ( !r->isNull( "status" ) )
            status = r->getString( "status" );
        recipient->setAction( action, status );

        if ( !r->isNull( "last_attempt" ) ) {
            Date * date = new Date;
            date->setUnixTime( r->getInt( "last_attempt" ) );
            recipient->setLastAttempt( date );
        }

        dsn->addRecipient( recipient );
    }

    return dsn;
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
    StringList l;

    List<Recipient>::Iterator it( dsn->recipients() );
    while ( it ) {
        Recipient * r = it;
        if ( r->action() == Recipient::Unknown ) {
            active++;
            Address * a = r->finalRecipient();
            l.append( a->localpart() + "@" + a->domain() );
        }
        ++it;
    }

    log( "Sending to " + l.join( "," ) +
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

    Injector * i = new Injector( dsn->result(), this );
    i->setDeliveryAddresses( l );
    i->setSender( new Address( "", "", "" ) );
    return i;
}


static GraphableCounter * messagesSent = 0;


/*! Updates the row in deliveries matching \a delivery, as well as any
    related rows in delivery_recipients, based on the status of \a dsn.
    Returns the number of recipients for whom delivery is pending. The
    queries needed to perform the update are enqueued directly into
    d->t, for the caller to execute at will.
*/

uint DeliveryAgent::updateDelivery( uint delivery, DSN * dsn )
{
    d->update =
        new Query( "update deliveries set tried_at=current_timestamp "
                   "where id=$1", this );
    d->update->bind( 1, delivery );
    d->t->enqueue( d->update );

    uint handled = 0;
    uint unhandled = 0;
    List<Recipient>::Iterator it( dsn->recipients() );
    while ( it ) {
        Recipient * r = it;
        ++it;
        if ( r->action() == Recipient::Unknown ||
             r->action() == Recipient::Delayed )
        {
            unhandled++;
        }
        else {
            // XXX: Using current_timestamp here makes testing harder.
            Query * q =
                new Query( "update delivery_recipients "
                           "set action=$1, status=$2, "
                           "last_attempt=current_timestamp "
                           "where delivery=$3 and recipient=$4",
                           this );
            q->bind( 1, (int)r->action() );
            q->bind( 2, r->status() );
            q->bind( 3, delivery );
            q->bind( 4, r->finalRecipient()->id() );
            d->t->enqueue( q );
            handled++;
        }
    }

    if ( dsn->allOk() ) {
        log( "Delivered successfully to " +
             fn( handled ) + " recipients" );
        if ( !::messagesSent )
            ::messagesSent = new GraphableCounter( "messages-sent" );
        ::messagesSent->tick();
    }
    // XXX at this point we probably want to do
    //   else if ( !unhandled ) {
    //       ...send a DSN...
    //   }
    else {
        log( "Recipients handled: " + fn( handled ) +
             ", still queued: " + fn( unhandled ) );
    }

    return unhandled;
}
