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


class DeliveryAgentData
    : public Garbage
{
public:
    DeliveryAgentData()
        : log( 0 ), mailbox( 0 ), uid( 0 ), owner( 0 ),
          t( 0 ), q( 0 ), sender( 0 ), message( 0 ), dsn( 0 ),
          client( 0 ), sent( false ),
          done( false ), delivered( false )
    {}

    Log * log;
    Mailbox * mailbox;
    uint uid;
    EventHandler * owner;
    Transaction * t;
    Query * q;
    Address * sender;
    List<Recipient> recipients;
    Message * message;
    DSN * dsn;
    SmtpClient * client;
    bool sent;
    bool done;
    bool delivered;
};


/*! \class DeliveryAgent deliveryagent.h
    Responsible for attempting to deliver a queued message and updating
    the corresponding row in the deliveries table.
*/

/*! Creates a new DeliveryAgent object to deliver the message in
    \a mailbox with \a uid. The \a owner will be notified upon
    completion.
*/

DeliveryAgent::DeliveryAgent( Mailbox * mailbox, uint uid,
                              EventHandler * owner )
    : d( new DeliveryAgentData )
{
    d->mailbox = mailbox;
    d->uid = uid;
    d->owner = owner;
    d->log = new Log( Log::SMTP );
}


void DeliveryAgent::execute()
{
    Scope x( d->log );

    if ( !d->t ) {
        d->t = new Transaction( this );
        d->q =
            new Query( "select d.id, "
                       "f.localpart as s_localpart, f.domain as s_domain, "
                       "t.localpart as r_localpart, t.domain as r_domain, "
                       "current_timestamp > expires_at as expired "
                       "from deliveries d "
                       "join addresses f on (d.sender=f.id) "
                       "join addresses t on (d.recipient=t.id) "
                       "where mailbox=$1 and uid=$2 and "
                       "delivered_at is null and "
                       "(tried_at is null or"
                       " tried_at+interval '1 hour' < current_timestamp)",
                       this );
        d->q->bind( 1, d->mailbox->id() );
        d->q->bind( 2, d->uid );
        d->t->enqueue( d->q );
        d->t->execute();
    }

    if ( !d->message ) {
        if ( !d->q->done() )
            return;

        if ( d->q->rows() == 0 ) {
            d->done = true;
            d->delivered = false;
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
        while ( d->q->hasResults() ) {
            Row * r = d->q->nextRow();

            if ( r->isNull( "expired" ) ||
                 r->getBoolean( "expired" ) == false )
            {
                String rl( r->getString( "r_localpart" ) );
                String rd( r->getString( "r_domain" ) );
                Address * rAddress = new Address( "", rl, rd );
                Recipient * recipient = new Recipient;
                recipient->setFinalRecipient( rAddress );
                d->dsn->addRecipient( recipient );

                // XXX: WTF!@# We want to fetch (sender,[recipients]).
                String sl( r->getString( "s_localpart" ) );
                String sd( r->getString( "s_domain" ) );
                Address * sender = new Address( "", sl, sd );
                d->dsn->setSender( sender );
            }
        }

        if ( d->dsn->recipients()->isEmpty() ) {
            d->done = true;
            d->delivered = false;
            d->owner->execute();
            return;
        }
    }

    if ( !d->client ) {
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

    // XXX: ?
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
