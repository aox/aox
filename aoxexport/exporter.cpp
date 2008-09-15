// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "exporter.h"

#include "transaction.h"
#include "eventloop.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"
#include "query.h"
#include "date.h"
#include "list.h"

#include <unistd.h> // write()


class ExporterData
    : public Garbage
{
public:
    ExporterData()
        : transaction( 0 ), find( 0 ), fetcher( 0 ),
          mailbox( 0 ), messages( new List<Message> )
        {}

    Transaction * transaction;
    Query * find;
    Fetcher * fetcher;
    UString sourceName;
    Mailbox * mailbox;
    List<Message> * messages;
};


static const char * months[] = { "Jan", "Feb", "Mar", "Apr",
                                 "May", "Jun", "Jul", "Aug",
                                 "Sep", "Oct", "Nov", "Dec" };

static const char * weekdays[] = { "Mon", "Tue", "Wed", "Thu",
                                   "Fri", "Sat", "Sun" };


/*! Constructs an Exporter object which will read the messages in \a
    source and write them to stdout.
    
    What happens if \a source is not a valid mailbox? Time will show
*/

Exporter::Exporter( const UString & source )
    : d( new ExporterData )
{
    d->sourceName = source;
    setLog( new Log( Log::General ) );
}


void Exporter::execute()
{
    if ( Mailbox::refreshing() ) {
        Database::notifyWhenIdle( this );
        return;
    }

    if ( !d->mailbox ) {
        d->mailbox = Mailbox::find( d->sourceName );
        if ( !d->mailbox ) {
            log( "No such mailbox: " + d->sourceName.utf8(),
                 Log::Disaster );
            return;
        }
    }

    if ( !d->transaction ) {
        d->transaction = new Transaction( this );
        d->find = new Query( "select uid from mailbox_messages "
                             "where mailbox=$1 order by uid for update",
                             this );
        d->find->bind( 1, d->mailbox->id() );
        d->transaction->enqueue( d->find );
        d->transaction->execute();
    }

    if ( !d->find->done() )
        return;

    if ( !d->fetcher ) {
        while ( d->find->hasResults() ) {
            Row * r = d->find->nextRow();
            Message * m = new Message;
            m->setUid( d->mailbox, r->getInt( "uid" ) );
            d->messages->append( m );
        }
        d->fetcher = new Fetcher( d->mailbox, d->messages, this );
        d->fetcher->fetch( Fetcher::Addresses );
        d->fetcher->fetch( Fetcher::OtherHeader );
        d->fetcher->fetch( Fetcher::Body );
        d->fetcher->fetch( Fetcher::Trivia );
        d->fetcher->setTransaction( d->transaction );
        d->fetcher->execute();
    }

    while ( !d->messages->isEmpty() ) {
        Message * m = d->messages->firstElement(); 
        if ( !m->hasAddresses() )
            return;
        if ( !m->hasHeaders() )
            return;
        if ( !m->hasBodies() )
            return;
        if ( !m->hasTrivia( d->mailbox ) )
            return;
        d->messages->shift();
        String from = "From ";
        Header * h = m->header();
        List<Address> * rp = 0;
        if ( h ) {
            rp = h->addresses( HeaderField::ReturnPath );
            if ( !rp )
                rp = h->addresses( HeaderField::Sender );
            if ( !rp )
                rp = h->addresses( HeaderField::From );
        }
        if ( rp )
            from.append( rp->firstElement()->lpdomain() );
        else
            from.append( "invalid@invalid.invalid" );
        Date id;
        id.setUnixTime( m->internalDate( d->mailbox ) );
        from.append( " " );
        // Tue Jul 23 19:39:23 2002
        from.append( weekdays[id.weekday()] );
        from.append( " " );
        from.append( months[id.month()-1] );
        from.append( " " );
        from.append( fn( id.day() ) );
        from.append( " " );
        from.append( fn( id.hour() ) );
        from.append( ":" );
        if ( id.minute() < 10 )
            from.append( "0" );
        from.append( fn( id.minute() ) );
        from.append( ":" );
        if ( id.second() < 10 )
            from.append( "0" );
        from.append( fn( id.second() ) );
        from.append( " " );
        from.append( fn( id.year() ) );
        from.append( "\r\n" );
        String rfc822 = m->rfc822();
        ::write( 1, from.data(), from.length() );
        ::write( 1, rfc822.data(), rfc822.length() );
    }

    d->transaction->commit();
    if ( d->transaction->done() )
        EventLoop::global()->stop();

}

