#include "fetcher.h"

#include "messageset.h"
#include "annotation.h"
#include "allocator.h"
#include "bodypart.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "query.h"
#include "flag.h"
#include "utf.h"


class FetcherData
    : public Garbage
{
public:
    FetcherData()
        : owner( 0 ),
          mailbox( 0 ), query( 0 ),
          smallest( 0 ), largest( 0 ),
          uid( 0 ), notified( 0 ), message( 0 )
    {}

    List<Message> messages;
    EventHandler * owner;
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
static PreparedStatement * trivia;
static PreparedStatement * flags;
static PreparedStatement * body;
static PreparedStatement * anno;


static void setupPreparedStatements()
{
    if ( ::header )
        return;

    const char * q =
        "select h.uid, h.part, f.name, h.value from "
        "header_fields h, field_names f where "
        "h.field = f.id and "
        "h.uid>=$1 and h.uid<=$2 and h.mailbox=$3 "
        "order by h.uid, h.part, h.position";
    ::header = new PreparedStatement( q );
    q = "select m.uid, m.idate, m.rfc822size, ms.modseq::int from messages m "
        "left join modsequences ms using (mailbox,uid) "
        "where m.uid>=$1 and m.uid<=$2 and m.mailbox=$3 "
        "order by m.uid";
    ::trivia = new PreparedStatement( q );
    q = "select p.uid, p.part, b.text, b.data, "
        "b.bytes as rawbytes, p.bytes, p.lines "
        "from part_numbers p left join bodyparts b on p.bodypart=b.id "
        "where p.uid>=$1 and p.uid<=$2 and p.mailbox=$3 and p.part != '' "
        "order by p.uid, p.part";
    ::body = new PreparedStatement( q );
    q = "select uid, flag from flags "
        "where uid>=$1 and uid<=$2 and mailbox=$3 "
        "order by uid, flag";
    ::flags = new PreparedStatement( q );
    q = "select a.uid, a.owner, a.value, an.name, an.id "
        "from annotations a, annotation_names an "
        "where a.uid>=$1 and a.uid<=$2 and a.mailbox=$3 "
        "and a.name=an.id "
        "order by a.uid, an.id, a.owner";
    ::anno = new PreparedStatement( q );
    Allocator::addEternal( header, "statement to fetch headers" );
    Allocator::addEternal( trivia, "statement to fetch approximately nothing" );
    Allocator::addEternal( body, "statement to fetch bodies" );
    Allocator::addEternal( flags, "statement to fetch flags" );
    Allocator::addEternal( anno, "statement to fetch annotations" );
}


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


/*! Constructs an empty Fetcher which will fetch \a messages in
    mailbox \a m and notify \a e when it's done. */

Fetcher::Fetcher( Mailbox * m, List<Message> * messages, EventHandler * e )
    : EventHandler(), d( new FetcherData )
{
    setupPreparedStatements();
    d->mailbox = m;
    d->owner = e;
    List<Message>::Iterator i( messages );
    while ( i ) {
        d->messages.append( i );
        ++i;
    }
    execute();
}


/*! Returns true if this Fetcher has finished the work assigned to it
    (and will perform no further message updates), and false if it is
    still working.
*/

bool Fetcher::done() const
{
    return !d->query;
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
            if ( !d->message || d->message->uid() != d->uid ) {
                List<Message>::Iterator i( d->messages );
                while ( i && i->uid() < d->uid )
                    i++;
                if ( i->uid() == d->uid )
                    d->message = i;
                else
                    d->message = 0;
            }
            if ( d->message )
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

    d->results.clear();
    d->owner->execute();

    if ( d->query )
        return;

    MessageSet still;
    List<Message>::Iterator i( d->messages );
    while ( i ) {
        still.add( i->uid() );
        ++i;
    }
    // now, what to do. if we've been asked to fetch a simple range,
    // do it.
    d->smallest = still.smallest();
    if ( still.isRange() ) {
        d->largest = still.largest();
    }
    else {
        // if not, make a range that encompasses up to four additional
        // messages (or at least UIDs)
        uint i = 1;
        while ( i <= still.count() && still.value( i ) - d->smallest < i + 4 )
            d->largest = still.value( i++ );
    }
    d->query = new Query( *query(), this );
    d->query->bind( 1, d->smallest );
    d->query->bind( 2, d->largest );
    d->query->bind( 3, d->mailbox->id() );
    d->query->execute();
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
    List<Message>::Iterator i( d->messages );
    while ( i && i->uid() < uid ) {
        setDone( (Message*)i );
        d->messages.take( i );
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
        if ( !bp->message() ) {
            bp->setMessage( new Message );
            bp->message()->setParent( bp );
        }
        h = bp->message()->header();
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
        List<Flag> * flags = m->flags();
        List<Flag>::Iterator i( flags );
        while ( i && i != f )
            ++i;
        if ( !i )
            flags->append( f );
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
        if ( !bp->message() ) {
            bp->setMessage( new Message );
            bp->message()->setParent( bp );
        }

        List< Bodypart >::Iterator it( bp->children() );
        while ( it ) {
            bp->message()->children()->append( it );
            ++it;
        }
    }
    else {
        Bodypart * bp = m->bodypart( part, true );

        // We would like to ask for "coalesce(data,text) as data" here
        // so as to avoid fetching text unnecessarily, but bytea can't
        // be coalesced with text.

        if ( !r->isNull( "data" ) ) {
            bp->setData( r->getString( "data" ) );
        }
        else if ( !r->isNull( "text" ) ) {
            PgUtf8Codec p;
            Utf8Codec u;
            String s = r->getString( "text" );
            bp->setData( u.fromUnicode( p.toUnicode( s ) ) );
        }

        if ( !r->isNull( "rawbytes" ) )
            bp->setNumBytes( r->getInt( "rawbytes" ) );
        if ( !r->isNull( "bytes" ) )
            bp->setNumEncodedBytes( r->getInt( "bytes" ) );
        if ( !r->isNull( "lines" ) )
            bp->setNumEncodedLines( r->getInt( "lines" ) );
    }
}


void MessageBodyFetcher::setDone( Message * m )
{
    m->setBodiesFetched();
}

/*! \class MessageTriviaFetcher fetcher.h

    The MessageTriviaFetcher class is an implementation class
    responsible for fetching, ah, well, for fetching the IMAP
    internaldate and rfc822.size.

    It has no API of its own and precious little code; Fetcher is the
    entire API.
*/

/*! \fn MessageTriviaFetcher::MessageTriviaFetcher( Mailbox * m )

    Constructs a Fetcher to fetch two trivial, stupid little columns
    for the messages in \a m.
*/


PreparedStatement * MessageTriviaFetcher::query() const
{
    return ::trivia;
}


void MessageTriviaFetcher::decode( Message * m , Row * r )
{
    m->setInternalDate( r->getInt( "idate" ) );
    m->setRfc822Size( r->getInt( "rfc822size" ) );
    if ( !r->isNull( "modseq" ) )
        m->setModSeq( r->getInt( "modseq" ) );
}


void MessageTriviaFetcher::setDone( Message * )
{
    // hard work
}


/*! \class MessageAnnotationFetcher message.h

    This class fetches the annotations for a message. Both the shared
    annotations and all private annotations are fetched at once.
*/

PreparedStatement * MessageAnnotationFetcher::query() const
{
    return ::anno;
}


void MessageAnnotationFetcher::decode( Message * m, Row * r )
{
    AnnotationName * an = AnnotationName::find( r->getInt( "id" ) );
    if ( !an ) {
        an = new AnnotationName( r->getString( "name" ), r->getInt( "id" ) );
        (void)new AnnotationNameFetcher( 0 ); // why create this, really?
    }

    Annotation * a = new Annotation;
    a->setEntryName( an );

    uint owner = 0;
    if ( !r->isNull( "owner" ) )
        owner = r->getInt( "owner" );
    a->setOwnerId( owner );
    a->setValue( r->getString( "value" ) );

    m->replaceAnnotation( a );
}


void MessageAnnotationFetcher::setDone( Message * m )
{
    m->setAnnotationsFetched();
}
