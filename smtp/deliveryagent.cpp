// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "deliveryagent.h"

#include "log.h"
#include "scope.h"
#include "query.h"
#include "transaction.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"
#include "smtpclient.h"
#include "dsn.h"
#include "address.h"
#include "recipient.h"
#include "injector.h"
#include "spoolmanager.h"
#include "date.h"
#include "stringlist.h"


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : log( 0 ), mailbox( 0 ), uid( 0 ), owner( 0 ),
          t( 0 ), qm( 0 ), qs( 0 ), qr( 0 ), deliveryRow( 0 ),
          message( 0 ), dsn( 0 ), injector( 0 ), update( 0 ),
          senders( 0 ), sent( 0 ), client( 0 )
    {}

    Log * log;
    Mailbox * mailbox;
    uint uid;
    EventHandler * owner;
    Transaction * t;
    Query * qm;
    Query * qs;
    Query * qr;
    Row * deliveryRow;
    Message * message;
    DSN * dsn;
    Injector * injector;
    Query * update;
    uint senders;
    uint sent;
    SmtpClient * client;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*! Creates a new DeliveryAgent object to deliver the message in
    \a mailbox with \a uid using the specified SMTP \a client. The
    \a owner will be notified upon completion.
*/

DeliveryAgent::DeliveryAgent( SmtpClient * client,
                              Mailbox * mailbox, uint uid,
                              EventHandler * owner )
    : d( new DeliveryAgentData )
{
    d->log = new Log( Log::SMTP );
    Scope x( d->log );
    log( "Starting delivery attempt for " +
         mailbox->name() + ":" + fn( uid ) );
    d->client = client;
    d->mailbox = mailbox;
    d->uid = uid;
    d->owner = owner;
}


void DeliveryAgent::execute()
{
    Scope x( d->log );

    // Fetch and lock all pending deliveries for (mailbox,uid).

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->qm = fetchDeliveries( d->mailbox, d->uid );
        d->t->enqueue( d->qm );
        d->t->execute();
    }

    // Count each delivery, and either try to deliver it right away, or
    // leave it until enough time has passed to try it again.

    while ( d->deliveryRow || ( d->qm && d->qm->hasResults() ) ) {

        // If we're not processing a delivery already, we'll look for
        // the next one that we can attempt immediately.

        if ( !d->deliveryRow ) {
            do {
                d->deliveryRow = d->qm->nextRow();
                d->senders++;
                if ( d->deliveryRow->getBoolean( "can_retry" ) == true )
                    break;
                d->deliveryRow = 0;
            }
            while ( d->qm->hasResults() );

            // If there isn't one, we're done.
            if ( !d->deliveryRow )
                break;
        }

        // Fetch the sender address, the relevant delivery_recipients
        // entries, and the message itself. (If we're called again for
        // the same message after we've completed delivery, we'll do a
        // lot of work before realising that nothing needs to be done.)

        if ( !d->message ) {
            d->message = fetchMessage( d->mailbox, d->uid );

            d->qs = fetchSender( d->deliveryRow->getInt( "sender" ) );
            d->t->enqueue( d->qs );

            d->qr = fetchRecipients( d->deliveryRow->getInt( "id" ) );
            d->t->enqueue( d->qr );

            d->t->execute();
        }

        if ( !d->qs->done() || !d->qr->done() )
            return;

        if ( !( d->message->hasHeaders() &&
                d->message->hasAddresses() &&
                d->message->hasBodies() ) )
            return;

        if ( !d->client->ready() )
            return;

        // Now we're ready to process the delivery. We create a DSN, set
        // the message, sender, and the recipients, then decide whether
        // to send the message.

        if ( !d->dsn ) {
            d->dsn = createDSN( d->message, d->qs, d->qr );

            if ( d->dsn->deliveriesPending() ) {
                if ( !d->deliveryRow->isNull( "expired" ) &&
                     d->deliveryRow->getBoolean( "expired" ) == true )
                {
                    expireRecipients( d->dsn );
                }
                else {
                    logDelivery( d->dsn );
                    d->client->send( d->dsn, this );
                }
            }
            else {
                // We'll just skip to the next delivery. Instead of
                // using continue, though, we'll...
                d->deliveryRow = 0;
                d->sent++;
            }
        }

        if ( d->dsn->deliveriesPending() )
            return;

        // At this point, the SmtpClient has updated the action and
        // status for each recipient. Now we decide whether or not
        // to spool a bounce message.

        if ( d->deliveryRow && !d->update && !d->injector ) {
            if ( d->dsn->allOk() )
                d->sent++;
            else
                d->injector = injectBounce( d->dsn );

            if ( d->injector )
                d->injector->execute();
        }

        if ( d->injector && !d->injector->done() )
            return;

        // Once we're done delivering (or bouncing) the message, we'll
        // update the relevant rows in delivery_recipients, so that we
        // know what to do next time around.

        if ( d->deliveryRow && !d->update ) {
            uint unhandled =
                updateDelivery( d->deliveryRow->getInt( "id" ), d->dsn );

            if ( unhandled == 0 )
                d->sent++;

            d->t->execute();
        }

        if ( d->update && !d->update->done() )
            return;

        d->deliveryRow = 0;
        d->injector = 0;
        d->message = 0;
        d->update = 0;
        d->dsn = 0;
    }

    if ( d->qm && d->qm->done() ) {
        d->t->commit();
        d->qm = 0;
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        // We might end up resending copies of messages that we couldn't
        // update during this transaction. I could split up the code so
        // that each (sender,mailbox,uid) gets its own transaction, but
        // at least one message will always be at risk of repetition.
        // Since the common case is a single matching row, it doesn't
        // seem worthwhile.
        log( "Delivery attempt failed due to database error: " +
             d->t->error(), Log::Error );
        log( "Shutting down spool manager.", Log::Error );
        SpoolManager::shutdown();
    }

    // We're done() now. What we did can be gauged by delivered().

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
    return d->senders == d->sent;
}


/*! Returns a pointer to a Query that selects and locks all rows from
    deliveries that match the given \a mailbox and \a uid.
*/

Query * DeliveryAgent::fetchDeliveries( Mailbox * mailbox, uint uid )
{
    Query * q =
        new Query(
            "select id, sender, "
            "current_timestamp > expires_at as expired, "
            "(tried_at is null or tried_at+interval '1 hour'"
            " < current_timestamp) as can_retry "
            "from deliveries where mailbox=$1 "
            "and uid=$2 for update", this
        );
    q->bind( 1, mailbox->id() );
    q->bind( 2, uid );
    return q;
}


/*! Begins to fetch a message with the given \a uid from \a mailbox, and
    returns a pointer to the newly-created Message object, which will be
    filled in by the message fetchers.
*/

Message * DeliveryAgent::fetchMessage( Mailbox * mailbox, uint uid )
{
    Message * m = new Message;
    m->setUid( uid );

    List<Message> l;
    l.append( m );

    Fetcher * f;
    f = new MessageHeaderFetcher( mailbox, &l, this );
    f->execute();

    f = new MessageAddressFetcher( mailbox, &l, this );
    f->execute();

    f = new MessageBodyFetcher( mailbox, &l, this );
    f->execute();

    return m;
}


/*! Returns a pointer to a Query to fetch the address information for a
    message sender with the given \a sender id.
*/

Query * DeliveryAgent::fetchSender( uint sender )
{
    // We fetch the sender address separately because we don't (and
    // should not) have UPDATE privileges on addresses, so we can't
    // join to addresses in fetchDeliveries().
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
    // XXX: We go just a little too far to fetch last_attempt
    // in RFC822 format here. The right thing would be to add
    // timestamptz support to Query/PgMessage.
    Query * q =
        new Query(
            "select recipient,localpart,domain,action,status,"
            "to_char(last_attempt,'DD Mon YYYY HH24:MI:SS ')||"
            "to_char((extract(timezone from last_attempt)/60) + "
            "40*((extract(timezone from last_attempt)/60)"
            "::integer/60), 'SG0000') as last_attempt "
            "from delivery_recipients join addresses "
            "on (recipient=addresses.id) "
            "where delivery=$1", this
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
            date->setRfc822( r->getString( "last_attempt" ) );
            recipient->setLastAttempt( date );
        }

        dsn->addRecipient( recipient );
    }

    return dsn;
}


/*! Updates all recipients for the given \a dsn to reflect that the
    message delivery request has expired, and logs a message to that
    effect.
*/

void DeliveryAgent::expireRecipients( DSN * dsn )
{
    List<Recipient>::Iterator it( dsn->recipients() );
    while ( it ) {
        Recipient * r = it;
        if ( r->action() == Recipient::Unknown )
            r->setAction( Recipient::Failed, "Expired" );
        ++it;
    }

    log( "Delivery for message " + fn( dsn->message()->uid() ) +
         " expired" );
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

    log( "Attempting delivery to " + l.join( "," ) +
         " (" + fn( active ) + " of " + fn( total ) +
         " recipients)" );
}


/*! Returns a pointer to a newly-created Injector to inject a bounce
    message derived from the specified \a dsn, or 0 if it can't find
    the spool mailbox, or if the DSN was for a bounce already. The
    caller must call Injector::execute() when appropriate.
*/

Injector * DeliveryAgent::injectBounce( DSN * dsn )
{
    Mailbox * m = Mailbox::find( "/archiveopteryx/spool" );
    if ( !m )
        return 0;

    List<Address> * l = new List<Address>;
    if ( dsn->sender()->type() != Address::Normal )
        return 0;
    l->append( dsn->sender() );

    Injector * i = new Injector( dsn->result(), this );
    i->setDeliveryAddresses( l );
    i->setSender( new Address( "", "", "" ) );
    i->setMailbox( m );
    return i;
}


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

    log( "Recipients handled: " + fn( handled ) +
         ", still queued: " + fn( unhandled ) );

    return unhandled;
}
