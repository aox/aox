// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "spoolmanager.h"

#include "dsn.h"
#include "date.h"
#include "query.h"
#include "timer.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"
#include "injector.h"
#include "recipient.h"
#include "smtpclient.h"
#include "deliveryagent.h"


static SpoolManager * sm;


class SpoolManagerData
    : public Garbage
{
public:
    SpoolManagerData()
        : q( 0 )
    {}

    Query * q;
    Timer * t;
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
    if ( !d->q ) {
        d->q =
            new Query( "select distinct (mailbox,uid) from deliveries d "
                       "left join deleted_messages dm using (mailbox,uid) "
                       "where dm.uid is null and d.delivered_at is null",
                       this );
        d->q->execute();
        delete d->t;
        d->t = 0;
    }

    Row * r = 0;
    while ( ( r = d->q->nextRow() ) ) {
        Mailbox * m = Mailbox::find( r->getInt( "mailbox" ) );
        if ( m )
            (void)new DeliveryAgent( m, r->getInt( "uid" ) );
    }

    if ( d->q->done() ) {
        d->q = 0;
        d->t = new Timer( this, 300 );
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
