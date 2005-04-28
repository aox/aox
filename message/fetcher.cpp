#include "fetcher.h"

#include "messageset.h"
#include "allocator.h"
#include "bodypart.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "query.h"
#include "flag.h"
#include "utf.h"


class FetcherData {
public:
    FetcherData()
        : mailbox( 0 ), query( 0 ),
          smallest( 0 ), largest( 0 ),
          uid( 0 ), notified( 0 ), message( 0 )
    {}
    struct Handler {
        Handler(): o( 0 ) {}
        MessageSet s;
        EventHandler * o;
    };

    List<Handler> handlers;
    Mailbox * mailbox;
    Query * query;
    uint smallest;
    uint largest;
    uint uid;
    uint notified;
    Message * message;
    MessageSet results;
};


static PreparedStatement * header;
static PreparedStatement * flags;
static PreparedStatement * body;


/*! \class Fetcher fetcher.h

    The Fetcher class retrieves Message data for some/all messages in
    a Mailbox. It's an abstract base class that manages the Message
    and Mailbox aspects of the job; subclasses provide the Query or
    PreparedStatement necessary to fetch specific data.

    A Fetcher lives for a while, fetching data about a range of
    messages. Whenever it finishes its current retrieval, it finds the
    largest range of messages currently needing retrieval, and issues
    an SQL select for them. Typically the select ends with "uid>=x and
    uid<=y". When the Fetcher isn't useful any more, its Mailbox drops
    it on the floor.

    In consequence, we have at most one outstanding Query per Mailbox
    and type of query, and when it finishes a new is issued.
*/


/*! Constructs an empty Fetcher which will fetch messages in mailbox \a m. */

Fetcher::Fetcher( Mailbox * m )
    : EventHandler(), d( new FetcherData )
{
    d->mailbox = m;
    if ( !::header ) {
        const char * q =
            "select h.uid, h.part, f.name, h.value from "
            "header_fields h, field_names f where "
            "h.field = f.id and "
            "h.uid>=$1 and h.uid<=$2 and h.mailbox=$3 "
            "order by h.uid, h.part, h.id";
        ::header = new PreparedStatement( q );
        q = "select p.uid, p.part, b.text, b.data, "
            "b.bytes as rawbytes, p.bytes, p.lines "
            "from part_numbers p left join bodyparts b on p.bodypart=b.id "
            "where p.uid>=$1 and p.uid<=$2 and p.mailbox=$3 and p.part != '' "
            "order by p.uid, p.part";
        ::body = new PreparedStatement( q );
        q = "select uid, flag from flags "
            "where uid>=$1 and uid<=$2 and mailbox=$3 "
            "order by uid";
        ::flags = new PreparedStatement( q );
        Allocator::addEternal( header, "statement to fetch headers" );
        Allocator::addEternal( body, "statement to fetch bodies" );
        Allocator::addEternal( flags, "statement to fetch flags" );
    }
}


/*! This reimplementation of execute() calls decode() to decode data
    about each message, then notifies its owners that something was
    fetched.
*/

void Fetcher::execute()
{
    if ( d->query ) {
        Row * r;
        while ( (r=d->query->nextRow()) != 0 ) {
            d->uid = r->getInt( "uid" );
            d->message = d->mailbox->message( d->uid );
            d->results.add( d->uid );
            decode( d->message, r );
            setDone( d->uid );
        }
        if ( d->query->done() ) {
            d->query = 0;
            setDone( d->largest + 1 );
            d->notified = 0;
        }
    }

    if ( d->query && d->results.count() < 64 )
        return;

    if ( !d->results.isEmpty() ) {
        // if we've fetched something, notify the event handlers that
        // wait for that.
        List<FetcherData::Handler>::Iterator it( d->handlers );
        while ( it ) {
            List<FetcherData::Handler>::Iterator h( it );
            ++it;
            uint c = h->s.count();
            h->s.remove( d->results );
            if ( h->s.count() < c )
                h->o->execute();
            if ( h->s.isEmpty() )
                d->handlers.take( h );
        }
        d->results.clear();
    }

    if ( d->query )
        return;

    if ( d->smallest > 0 && d->largest >= d->smallest ) {
        // if the query is done and some event handlers are still
        // waiting for some data, forget that they asked for that
        // data, and notify them so they understand that it isn't
        // coming.
        List<FetcherData::Handler>::Iterator it( d->handlers );
        MessageSet s;
        s.add( d->smallest, d->largest );
        while ( it ) {
            List<FetcherData::Handler>::Iterator h( it );
            ++it;
            if ( !h->s.isEmpty() )
                h->o->execute();
            h->s.remove( s );
        }
    }

    MessageSet merged;
    List<FetcherData::Handler>::Iterator it( d->handlers );
    while ( it ) {
        merged.add( it->s );
        ++it;
    }
    if ( merged.isEmpty() ) {
        d->mailbox->forget( this );
        return;
    }
    // now, what to do. for the moment, we avoid even more messageset
    // magic and take the lowest-numbered message and a few more.
    // later, we'll want to be smarter.
    d->smallest = merged.smallest();
    uint i = 1;
    while ( i <= merged.count() && i < 512 &&
            merged.value( i ) - d->smallest < i + 4 )
        d->largest = merged.value( i++ );
    d->query = new Query( *query(), this );
    d->query->bind( 1, d->smallest );
    d->query->bind( 2, d->largest );
    d->query->bind( 3, d->mailbox->id() );
    d->query->execute();
}


/*! Tells this Fetcher to start fetching \a messages, and to notify \a
    handler when some/all of them have been fetched.
*/

void Fetcher::insert( const MessageSet & messages, EventHandler * handler )
{
    if ( messages.isEmpty() )
        return;
    FetcherData::Handler * h = new FetcherData::Handler;
    h->o = handler;
    h->s = messages;
    d->handlers.append( h );
    if ( !d->query )
        execute();
}


/*! \fn PreparedStatement * Fetcher::query() const

    Returns a prepared statement to fetch the appropriate sort of
    message data. The result must demand exactly three Query::bind()
    values, in order: The smallest UID for which data should be
    fetched, the largest, and the mailbox ID.
*/


/*! \fn void Fetcher::decode( Message * m, Row * r )

    This pure virtual function is responsible for decoding \a r and
    updating \a m with the results.
*/


/*! \fn void Fetcher::setDone( Message * m )

    This pure virtual function notifies \a m that this Fetcher has
    fetched all of the relevant data.
*/


/*! Notifies all messages up to but not including \a uid that they've
    been completely fetched.
*/

void Fetcher::setDone( uint uid )
{
    if ( d->notified == 0 )
        d->notified = d->smallest;

    while ( d->notified < uid ) {
        Message *m = d->mailbox->message( d->notified );
        if ( m )
            setDone( m );
        d->notified++;
    }
}



/*! \class MessageHeaderFetcher fetcher.h

    The MessageHeaderFetcher class is an implementation class
    responsible for fetching the headers of messages. It has no API of
    its own; Fetcher is the entire API.
*/


PreparedStatement * MessageHeaderFetcher::query() const
{
    return ::header;
}


void MessageHeaderFetcher::decode( Message * m, Row * r )
{
    String part = r->getString( "part" );
    String name = r->getString( "name" );
    String value = r->getString( "value" );

    Header *h = m->header();
    if ( part.endsWith( ".rfc822" ) ) {
        Bodypart * bp =
            m->bodypart( part.mid( 0, part.length()-7 ), true );
        if ( !bp->rfc822() )
            bp->setRfc822( new Message );
        h = bp->rfc822()->header();
    }
    else if ( !part.isEmpty() ) {
        h = m->bodypart( part, true )->header();
    }
    h->add( HeaderField::assemble( name, value ) );
}


void MessageHeaderFetcher::setDone( Message * m )
{
    m->setHeadersFetched();
}



/*! \class MessageFlagFetcher fetcher.h

    The MessageFlagFetcher class is an implementation class
    responsible for fetching the headers of messages. It has no API of
    its own; Fetcher is the entire API.
*/


PreparedStatement * MessageFlagFetcher::query() const
{
    return ::flags;
}


void MessageFlagFetcher::decode( Message * m, Row * r )
{
    Flag * f = Flag::find( r->getInt( "flag" ) );
    if ( f ) {
        m->flags()->append( f );
    }
    else {
        // XXX: consider this. best course of action may be to
        // silently ignore this flag for now. it's new, so we didn't
        // announce it in the select response, either. maybe we should
        // read the new flags, then invoke another MessageFlagFetcher.
    }
}


void MessageFlagFetcher::setDone( Message * m )
{
    m->setFlagsFetched( true );

}



/*! \class MessageBodyFetcher fetcher.h

    The MessageBodyFetcher class is an implementation class
    responsible for fetching the headers of messages. It has no API of
    its own; Fetcher is the entire API.
*/


PreparedStatement * MessageBodyFetcher::query() const
{
    return ::body;
}


void MessageBodyFetcher::decode( Message * m, Row * r )
{
    String part = r->getString( "part" );

    if ( part.endsWith( ".rfc822" ) ) {
        Bodypart *bp = m->bodypart( part.mid( 0, part.length()-7 ),
                                    true );
        if ( !bp->rfc822() )
            bp->setRfc822( new Message );

        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            bp->rfc822()->children()->append( it );
            ++it;
        }
    }
    else {
        Bodypart * bp = m->bodypart( part, true );

        if ( !r->isNull( "rawbytes" ) )
            bp->setNumBytes( r->getInt( "rawbytes" ) );
        if ( !r->isNull( "bytes" ) )
            bp->setNumEncodedBytes( r->getInt( "bytes" ) );
        if ( !r->isNull( "lines" ) )
            bp->setNumEncodedLines( r->getInt( "lines" ) );

        if ( !r->isNull( "text" ) )
            bp->setData( r->getString( "text" ) );
        else if ( !r->isNull( "data" ) )
            bp->setData( r->getString( "data" ) );
    }
}


void MessageBodyFetcher::setDone( Message * m )
{
    m->setBodiesFetched();
}
