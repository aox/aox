// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "spoolmanager.h"

#include "query.h"
#include "timer.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"


static SpoolManager * sm;


class SpoolManagerData
    : public Garbage
{
public:
    SpoolManagerData()
        : state( 0 ), q( 0 ), message( 0 ), deliveryId( 0 ),
          client( 0 )
    {}

    int state;
    Query * q;
    Message * message;
    uint deliveryId;
    Query * client;
};


/*! \class SpoolManager spoolmanager.h
    This class periodically attempts to deliver mail from the special
    /archiveopteryx/spool mailbox to a smarthost.
*/

SpoolManager::SpoolManager()
    : d( new SpoolManagerData )
{
}


void SpoolManager::execute()
{
    // Each time we're awoken, we issue this query until it returns no
    // more results.

    if ( d->state == 0 ||
         ( d->state == 1 && d->q->done() && d->q->rows() != 0 ) )
    {
        d->state = 1;
        d->q =
            new Query( "select * from deliveries where tried_at is null or "
                       "tried_at+'1 hour'::interval < current_timestamp",
                       this );
        d->q->execute();
    }

    // We attempt a delivery for each result we do retrieve.

    while ( d->state == 1 ) {
        if ( !d->message ) {
            if ( !d->q->hasResults() )
                break;

            Row * r = d->q->nextRow();

            d->deliveryId = r->getInt( "id" );

            List<Message> messages;
            d->message = new Message;
            d->message->setUid( r->getInt( "uid" ) );
            Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
            messages.append( d->message );

            Fetcher * f;
            f = new MessageHeaderFetcher( m, &messages, this );
            f->execute();

            f = new MessageAddressFetcher( m, &messages, this );
            f->execute();

            f = new MessageBodyFetcher( m, &messages, this );
            f->execute();
        }

        if ( !( d->message->hasHeaders() &&
                d->message->hasAddresses() &&
                d->message->hasBodies() ) )
            return;

        if ( !d->client ) {
            // XXX: This should be an SmtpClient, of course.
            d->client = new Query( "foo bar", this );
            d->client->execute();
        }

        if ( !d->client->done() )
            return;

        Query * q;
        if ( d->client->failed() )
            q = new Query( "update deliveries set tried_at=current_timestamp "
                           "where id=$1", 0 );
        else
            q = new Query( "delete from deliveries where id=$1", 0 );
        q->bind( 1, d->deliveryId );
        q->execute();

        d->message = 0;
        d->client = 0;
    }

    // And when there are no more, we go to sleep until we can expect to
    // have something to do.

    if ( d->state == 1 && d->q->done() ) {
        d->state = 0;
        (void)new Timer( this, 60 );
    }
}


/*! Causes the spool manager to re-examine the queue and attempt to make
    one or more deliveries, if possible.
*/

void SpoolManager::run()
{
    if ( !::sm )
        ::sm = new SpoolManager;
    ::sm->execute();
}
