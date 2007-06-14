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


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : log( 0 ), mailbox( 0 ), uid( 0 ), sid( 0 ), owner( 0 ),
          t( 0 ), q( 0 ), qr( 0 ), update( 0 ), row( 0 ), sender( 0 ),
          message( 0 ), dsn( 0 ), client( 0 ), injector( 0 ),
          sent( false ), done( false ), delivered( false )
    {}

    Log * log;
    Mailbox * mailbox;
    uint uid;
    uint sid;
    EventHandler * owner;
    Transaction * t;
    Query * q;
    Query * qr;
    Query * update;
    Row * row;
    Address * sender;
    Message * message;
    DSN * dsn;
    SmtpClient * client;
    Injector * injector;
    bool sent;
    bool done;
    bool delivered;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*! Creates a new DeliveryAgent object to deliver the message in
    \a mailbox with \a uid from \a sender. The \a owner will be
    notified upon completion.
*/

DeliveryAgent::DeliveryAgent( Mailbox * mailbox, uint uid, uint sender,
                              EventHandler * owner )
    : d( new DeliveryAgentData )
{
    d->mailbox = mailbox;
    d->uid = uid;
    d->sid = sender;
    d->owner = owner;
    d->log = new Log( Log::SMTP );
}


void DeliveryAgent::execute()
{
    Scope x( d->log );

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->q =
            new Query( "select d.id, f.localpart, f.domain, "
                       "current_timestamp > expires_at as expired "
                       "from deliveries d "
                       "join addresses f on (d.sender=f.id) "
                       "where mailbox=$1 and uid=$2 and sender=$3 and "
                       "delivered_at is null and "
                       "(tried_at is null or"
                       " tried_at+interval '1 hour' < current_timestamp)",
                       this );
        d->q->bind( 1, d->mailbox->id() );
        d->q->bind( 2, d->uid );
        d->q->bind( 2, d->sid );
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( !d->message ) {
        if ( !d->q->done() )
            return;

        if ( d->q->rows() == 0 ) {
            d->done = true;
            d->delivered = false;
            d->t->commit();
            d->owner->execute();
            return;
        }

        List<Message> messages;
        d->message = new Message;
        d->message->setUid( d->uid );
        messages.append( d->message );

        Fetcher * f;
        f = new MessageHeaderFetcher( d->mailbox, &messages, this );
        f->execute();

        f = new MessageAddressFetcher( d->mailbox, &messages, this );
        f->execute();

        f = new MessageBodyFetcher( d->mailbox, &messages, this );
        f->execute();
    }

    if ( !( d->message->hasHeaders() &&
            d->message->hasAddresses() &&
            d->message->hasBodies() ) )
        return;

    if ( !d->dsn ) {
        d->dsn = new DSN;
        d->dsn->setMessage( d->message );
        d->row = d->q->nextRow();
        d->qr =
            new Query( "select recipient, localpart, domain, action, "
                       "status from delivery_recipients "
                       "join addresses a on (recipient=a.id) "
                       "where delivery=$1", this );
        d->qr->bind( 1, d->row->getInt( "id" ) );
        d->t->enqueue( d->qr );
        d->t->execute();
    }

    if ( !d->qr->done() )
        return;

    if ( d->dsn->recipients()->isEmpty() ) {
        bool expired = false;
        if ( !d->row->isNull( "expired" ) )
            expired = d->row->getBoolean( "expired" );
        d->sender =
            new Address( "", d->row->getString( "localpart" ),
                         d->row->getString( "domain" ) );
        d->dsn->setSender( d->sender );

        while ( d->qr->hasResults() ) {
            Row * r = d->qr->nextRow();
            Address * a =
                new Address( "", r->getString( "localpart" ),
                             r->getString( "domain" ) );
            a->setId( r->getInt( "recipient" ) );
            Recipient * recipient = new Recipient;
            recipient->setFinalRecipient( a );
            recipient->setAction( (Recipient::Action)r->getInt( "action" ),
                                  r->getString( "status" ) );
            if ( expired )
                recipient->setAction( Recipient::Failed, "expired" );
            d->dsn->addRecipient( recipient );
        }

        if ( d->dsn->recipients()->isEmpty() ) {
            d->done = true;
            d->delivered = false;
            d->t->commit();
            d->owner->execute();
            return;
        }
    }

    if ( !d->client || !d->client->usable() ) {
        Endpoint e( Configuration::text( Configuration::SmartHostAddress ),
                    Configuration::scalar( Configuration::SmartHostPort ) );
        d->client = new SmtpClient( e, this );
    }

    if ( !d->client->ready() )
        return;

    if ( !d->sent ) {
        d->sent = true;
        d->client->send( d->dsn, this );
    }

    if ( d->dsn->deliveriesPending() )
        return;

    if ( !d->injector ) {
        if ( d->dsn->allOk() ) {
            d->delivered = true;
        }
        else {
            d->injector = new Injector( d->dsn->result(), this );
            d->injector->setMailbox( (Mailbox *)0 ); // XXX
            d->injector->execute();
        }
    }

    if ( d->injector && !d->injector->done() )
        return;

    if ( !d->update ) {
        String s( "update deliveries set " );
        if ( d->delivered )
            s.append( "delivered_at" );
        else
            s.append( "tried_at" );
        s.append( "=current_timestamp "
                  "where mailbox=$1 and uid=$2 and sender=$3" );

        d->update = new Query( s, this );
        d->update->bind( 1, d->mailbox->id() );
        d->update->bind( 2, d->uid );
        d->update->bind( 2, d->sid );
        d->t->enqueue( d->update );

        List<Recipient>::Iterator it( d->dsn->recipients() );
        while ( it ) {
            Recipient * r = it;
            Query * q =
                new Query( "update delivery_recipients "
                           "set action=$1, status=$2 where "
                           "delivery=$3 and recipient=$4", this );
            q->bind( 1, (int)r->action() );
            q->bind( 2, r->status() );
            q->bind( 3, d->row->getInt( "id" ) );
            q->bind( 4, r->finalRecipient()->id() );
            d->t->enqueue( q );
        }

        d->t->commit();
    }

    if ( !d->t->done() )
        return;

    if ( d->t->failed() ) {
        // XXX: What can we do now?
    }

    d->done = true;
    d->owner->execute();
}


/*! Returns true if this DeliveryAgent has finished processing
    deliveries for the message submitted to it.
*/

bool DeliveryAgent::done() const
{
    return d->done;
}


/*! Returns true if the message was delivered (or the delivery was
    permanently abandoned), and the spooled message may be deleted.
*/

bool DeliveryAgent::delivered() const
{
    return d->delivered;
}
