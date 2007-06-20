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
        : log( 0 ), mailbox( 0 ), uid( 0 ), owner( 0 ), t( 0 ),
          qm( 0 ), qs( 0 ), qr( 0 ), row( 0 ), message( 0 ),
          dsn( 0 ), injector( 0 ), update( 0 ), client( 0 ),
          delivered( false ), committed( false )
    {}

    Log * log;
    Mailbox * mailbox;
    uint uid;
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

    // Fetch and lock the row in deliveries matching (mailbox,uid).

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->qm = fetchDelivery( d->mailbox, d->uid );
        d->t->enqueue( d->qm );
        d->t->execute();
    }

    if ( !d->qm->done() )
        return;

    if ( d->qm->hasResults() ) {
        d->row = d->qm->nextRow();
        if ( d->row->getBoolean( "can_retry" ) == false )
            d->row = 0;
    }

    // Fetch the sender address, the relevant delivery_recipients
    // entries, and the message itself. (If we're called again for
    // the same message after we've completed delivery, we'll do a
    // lot of work before realising that nothing needs to be done.)

    if ( !d->message && d->row ) {
        d->message = fetchMessage( d->mailbox, d->uid );

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
                expireRecipients( d->dsn );
            }
            else {
                logDelivery( d->dsn );
                d->client->send( d->dsn, this );
            }
        }
        else {
            d->delivered = true;
            d->row = 0;
        }
    }

    // Once the SmtpClient has updated the action and status for each
    // recipient, we can decide whether or not to spool a bounce.

    if ( !d->injector && !d->update && d->row ) {
        if ( d->dsn->deliveriesPending() )
            return;

        if ( !d->dsn->allOk() )
            d->injector = injectBounce( d->dsn );

        if ( d->injector )
            d->injector->execute();
    }

    // Once we're done delivering (or bouncing) the message, we'll
    // update the relevant rows in delivery_recipients, so that we
    // know what to do next time around.

    if ( !d->update && d->row ) {
        if ( d->injector && !d->injector->done() )
            return;
        if ( d->injector )
            d->injector->announce();

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
    from deliveries that matches the given \a mailbox and \a uid.
*/

Query * DeliveryAgent::fetchDelivery( Mailbox * mailbox, uint uid )
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
