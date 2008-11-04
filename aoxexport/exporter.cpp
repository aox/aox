// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

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
        : find( 0 ), fetchers( 0 ),
          mailbox( 0 ), selector( 0 ),
          messages( new List<Message> )
        {}

    Query * find;
    List<Fetcher> * fetchers;
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
    setLog( new Log( Log::General ) );
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
        StringList wanted;
        wanted.append( "message" );
        wanted.append( "mailbox" );
        wanted.append( "uid" );
        d->find = d->selector->query( 0, d->mailbox, 0, this,
                                      true, &wanted, false );
        // we might select for update, to make sure the things don't
        // go away... but do we care? really?
        d->find->execute();
    }

    if ( !d->find->done() )
        return;

    if ( !d->fetchers ) {
        d->fetchers = new List<Fetcher>;
        Map<Fetcher> fetchers;
        Map<Message> messages;
        while ( d->find->hasResults() ) {
            Row * r = d->find->nextRow();
            Mailbox * mb = Mailbox::find( r->getInt( "mailbox" ) );
            if ( mb ) {
                Fetcher * f = fetchers.find( mb->id() );
                if ( !f ) {
                    f = new Fetcher( mb, new List<Message>, this );
                    d->fetchers->append( f );
                    fetchers.insert( mb->id(), f );
                }
                if ( !messages.contains( r->getInt( "message" ) ) ) {
                    Message * m = new Message;
                    messages.insert( r->getInt( "message" ), m );
                    m->setDatabaseId( r->getInt( "message" ) );
                    messages.insert( mb->id(), m );
                    m->setUid( mb, r->getInt( "uid" ) );
                    f->addMessage( m );
                    d->messages->append( m );
                }
            }
        }
        List<Fetcher>::Iterator f( d->fetchers );
        while ( f ) {
            f->fetch( Fetcher::Addresses );
            f->fetch( Fetcher::OtherHeader );
            f->fetch( Fetcher::Body );
            f->fetch( Fetcher::Trivia );
            f->execute();
            ++f;
        }
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

    EventLoop::global()->stop();
}

