// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "exporter.h"

#include "eventloop.h"
#include "selector.h"
#include "address.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"
#include "query.h"
#include "date.h"
#include "list.h"
#include "map.h"

#include <unistd.h> // write()


class ExporterData
    : public Garbage
{
public:
    ExporterData()
        : find( 0 ), fetcher( 0 ),
          mailbox( 0 ), selector( 0 ),
          messages( new List<Message> )
        {}

    Query * find;
    Fetcher * fetcher;
    UString sourceName;
    Mailbox * mailbox;
    Selector * selector;
    List<Message> * messages;
};


static const char * months[] = { "Jan", "Feb", "Mar", "Apr",
                                 "May", "Jun", "Jul", "Aug",
                                 "Sep", "Oct", "Nov", "Dec" };

static const char * weekdays[] = { "Sun", "Mon", "Tue", "Wed", "Thu",
                                   "Fri", "Sat" };


/*! Constructs an Exporter object which will read those messages in \a
    source which match \a selector and write them to stdout.

    If \a source is empty, the entire database is searched.

    If \a source is nonempty, but not a valid name, then the Exporter
    will kill the program with a disaster.
*/

Exporter::Exporter( const UString & source, Selector * selector )
    : d( new ExporterData )
{
    d->sourceName = source;
    d->selector = selector;
    setLog( new Log );
}


void Exporter::execute()
{
    if ( Mailbox::refreshing() ) {
        Database::notifyWhenIdle( this );
        return;
    }

    if ( !d->mailbox && !d->sourceName.isEmpty() ) {
        d->mailbox = Mailbox::find( d->sourceName );
        if ( !d->mailbox ) {
            log( "No such mailbox: " + d->sourceName.utf8(),
                 Log::Disaster );
            return;
        }
    }

    if ( !d->find ) {
        EStringList wanted;
        wanted.append( "message" );
        d->find = d->selector->query( 0, d->mailbox, 0, this,
                                      true, &wanted, false );
        d->find->execute();
    }

    if ( !d->find->done() )
        return;

    if ( !d->fetcher ) {
        d->messages = new List<Message>;
        while ( d->find->hasResults() ) {
            Row * r = d->find->nextRow();
            Message * m = new Message;
            m->setDatabaseId( r->getInt( "message" ) );
            d->messages->append( m );
        }
        d->fetcher = new Fetcher( d->messages, this, 0 );
        d->fetcher->fetch( Fetcher::Addresses );
        d->fetcher->fetch( Fetcher::OtherHeader );
        d->fetcher->fetch( Fetcher::Body );
        d->fetcher->fetch( Fetcher::Trivia );
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
        if ( !m->hasTrivia() )
            return;
        d->messages->shift();
        EString from = "From ";
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
        from.append( "  " );
        Date id;
        if ( m->internalDate() )
            id.setUnixTime( m->internalDate() );
        else if ( m->header()->date() )
            id = *m->header()->date();
        // Tue Jul 23 19:39:23 2002
        from.append( weekdays[id.weekday()] );
        from.append( " " );
        from.append( months[id.month()-1] );
        from.append( " " );
        from.appendNumber( id.day() );
        from.append( " " );
        from.appendNumber( id.hour() );
        from.append( ":" );
        if ( id.minute() < 10 )
            from.append( "0" );
        from.appendNumber( id.minute() );
        from.append( ":" );
        if ( id.second() < 10 )
            from.append( "0" );
        from.appendNumber( id.second() );
        from.append( " " );
        from.appendNumber( id.year() );
        from.append( "\r\n" );
        EString rfc822 = m->rfc822( false );
        int r = ::write( 1, from.data(), from.length() ) +
                ::write( 1, rfc822.data(), rfc822.length() );
        // we don't really care whether the write succeeds or not, so
        // just fool the compiler.
        r = r;
    }

    EventLoop::global()->stop();
}

