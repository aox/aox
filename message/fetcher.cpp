#include "fetcher.h"

#include "addressfield.h"
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
static PreparedStatement * address;
static PreparedStatement * oldAddress;
static PreparedStatement * trivia;
static PreparedStatement * flags;
static PreparedStatement * body;
static PreparedStatement * anno;


static void setupPreparedStatements()
{
    if ( ::header )
        return;

    const char * q =
        "select m.uid, h.part, h.position, f.name, h.value from "
        "mailbox_messages m join header_fields h using (message) "
        "join field_names f on (h.field=f.id) where "
        "h.field > 12 and m.uid>=$1 and m.uid<=$2 and m.mailbox=$3 "
        "order by m.uid, h.part";
    ::header = new PreparedStatement( q );

    q = "select m.uid, af.part, af.position, af.field, af.number, "
        "a.name, a.localpart, a.domain from "
        "mailbox_messages m join address_fields af using (message) "
        "join addresses a on (af.address=a.id) where "
        "m.uid>=$1 and m.uid<=$2 and m.mailbox=$3 "
        "order by m.uid, af.part, af.field, af.number ";
    ::address = new PreparedStatement( q );

    q = "select m.uid, h.part, h.position, f.name, h.value from "
        "mailbox_messages m join header_fields h using (message) "
        "join field_names f on (h.field=f.id) where "
        "h.field<=12 and m.uid>=$1 and m.uid<=$2 and m.mailbox=$3 "
        "order by m.uid, h.part";
    ::oldAddress = new PreparedStatement( q );

    q = "select m.id, mm.uid, mm.idate, m.rfc822size, mm.modseq "
        "from messages m join mailbox_messages mm on (mm.message=m.id) "
        "where mm.uid>=$1 and mm.uid<=$2 and mm.mailbox=$3 "
        "order by mm.uid";
    ::trivia = new PreparedStatement( q );

    q = "select m.uid, p.part, b.text, b.data, "
        "b.bytes as rawbytes, p.bytes, p.lines "
        "from mailbox_messages m join part_numbers p using (message) "
        "left join bodyparts b on (p.bodypart=b.id) where "
        "m.uid>=$1 and m.uid<=$2 and m.mailbox=$3 and p.part != '' "
        "order by m.uid, p.part";
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
    Allocator::addEternal( address, "statement to fetch address fields" );
    Allocator::addEternal( oldAddress,
                           "statement to fetch pre-1.13 address fields" );
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
    uid<=y". When the Fetcher isn't useful any more, its owner drops
    it on the floor.
*/


/*! Constructs an empty Fetcher which will fetch \a messages in
    mailbox \a m and notify \a e when it's done. */

Fetcher::Fetcher( Mailbox * m, List<Message> * messages, EventHandler * e )
    : EventHandler(), d( new FetcherData )
{
    setupPreparedStatements();
    d->mailbox = m;
    d->owner = e;
    addMessages( messages );
}


/*! Adds \a messages to the list of messages fetched. This does not
    re-execute the fetcher - the user must execute() it if done(). */

void Fetcher::addMessages( List<Message> * messages )
{
    List<Message>::Iterator i( messages );
    while ( i ) {
        d->messages.append( i );
        ++i;
    }
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
                if ( i && i->uid() == d->uid )
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

    bool notify = false;
    if ( !d->results.isEmpty() || d->smallest > 0 )
        notify = true;
    d->results.clear();
    if ( notify )
        d->owner->execute();

    if ( d->query )
        return;

    if ( d->messages.isEmpty() )
        return;

    List<Message>::Iterator i( d->messages );
    d->smallest = 0;
    d->largest = 0;
    if ( i )
        d->smallest = i->uid();
    uint n = 0;
    while ( i && n < 1024 ) {
        d->largest = i->uid();
        ++i;
        n++;
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
    UString value = r->getUString( "value" );

    Header * h = m->header();
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
    HeaderField * f = HeaderField::assemble( name, value );
    f->setPosition( r->getInt( "position" ) );
    h->add( f );
}


void MessageHeaderFetcher::setDone( Message * m )
{
    m->setHeadersFetched();
}



/*! \class MessageAddressFetcher fetcher.h

    The MessageAddressFetcher class is an implementation class
    responsible for fetching the address fields of messages. It has no
    API of its own; Fetcher is the entire API.
*/


PreparedStatement * MessageAddressFetcher::query() const
{
    return ::address;
}


void MessageAddressFetcher::decode( Message * m, Row * r )
{
    if ( r->isNull( "number" ) ) {
        if ( fallbackNeeded.last() != m )
            fallbackNeeded.append( m );
        l.clear();
        return;
    }
    String part = r->getString( "part" );
    uint position = r->getInt( "position" );

    // XXX: use something for mapping
    HeaderField::Type field = (HeaderField::Type)r->getInt( "field" );

    Header * h = m->header();
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
    AddressField * f = 0;
    uint n = 0;
    f = (AddressField*)h->field( field, 0 );
    while ( f && f->position() < position ) {
        n++;
        f = (AddressField*)h->field( field, n );
    }
    if ( !f || f->position() > position ) {
        f = new AddressField( field );
        f->setPosition( position );
        h->add( f );
        l.append( f );
    }
    Utf8Codec u;
    Address * a = new Address( r->getUString( "name" ),
                               r->getString( "localpart" ),
                               r->getString( "domain" ) );
    f->addresses()->append( a );
}


void MessageAddressFetcher::setDone( Message * m )
{
    if ( fallbackNeeded.last() == m )
        return;

    l.clear();

    m->setAddressesFetched();
}


/*! This reimplementation uses Fetcher::execute() and uses done() to
    check whether it needs to fall back to a MessageOldAddressFetcher
    when it's done its own work.
*/

void MessageAddressFetcher::execute()
{
    Fetcher::execute();
    if ( fallbackNeeded.isEmpty() )
        return;
    if ( !done() && d->smallest <= fallbackNeeded.last()->uid() )
         return;
    Fetcher * f = new MessageOldAddressFetcher( d->mailbox,
                                                &fallbackNeeded, d->owner );
    f->execute();
    fallbackNeeded.clear();
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

        if ( !r->isNull( "data" ) )
            bp->setData( r->getString( "data" ) );
        else if ( !r->isNull( "text" ) )
            bp->setText( r->getUString( "text" ) );

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
    internaldate, modseq and rfc822.size.

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
        m->setModSeq( r->getBigint( "modseq" ) );
}


void MessageTriviaFetcher::setDone( Message * )
{
    // hard work ;-)
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


/*! \class MessageOldAddressFetcher fetcher.h

    Until shortly before 1.13, the Injector did not inject as many
    address_fields rows as it should have. Because rectifying that in
    the database turned out to be an impossibly large task, we do it
    at read time. ("Impossibly large" means "a query took >24h to
    deliver its first row and it was no fun at all").

    If a message's address fields turn out to be incomplete when we
    read them (we know this because two addresses both claim to be
    first in the same list), MessageAddressFetcher switches to an
    alternate header reader: This class.
*/

/*! The same as the query() in MessageHeaderFetcher, except that it
    fetches the other header fields.
*/

PreparedStatement * MessageOldAddressFetcher::query() const
{
    return ::oldAddress;
}


void MessageOldAddressFetcher::setDone( Message * m )
{
    m->setAddressesFetched();
}


class MessageFetcherData
    : public Garbage
{
public:
    MessageFetcherData()
        : messageId( 0 ), message( 0 ), owner( 0 ),
          hf( 0 ), af( 0 ), bf( 0 )
    {}

    uint messageId;
    Message * message;
    EventHandler * owner;

    Query * hf;
    Query * af;
    Query * bf;
};


/*! \class MessageFetcher fetcher.h
    This class fetches a message by its message id.

    It exists solely for the use of the DeliveryAgent, which doesn't
    know the mailbox or uid of its victims; and in fact, the victims
    may not be in a mailbox at all (e.g. bounces). It duplicates the
    actions of the other *Fetchers to a great extent, but that can't
    be avoided, because they require a mailbox and uid to function.
*/

/*! Constructs a new MessageFetcher object to fetch the message with the
    given \a id. The \a owner is notified upon completion.
*/

MessageFetcher::MessageFetcher( uint id, EventHandler * owner )
    : d( new MessageFetcherData )
{
    d->messageId = id;
    d->message = new Message;
    d->owner = owner;
}


/*! Returns a pointer to the Message that this object is fetching
    details for. Will not be zero.
*/

Message * MessageFetcher::message() const
{
    return d->message;
}


void MessageFetcher::execute()
{
    if ( !d->hf ) {
        d->hf = new Query(
            "select h.part, h.position, f.name, h.value from "
            "header_fields h join field_names f on (h.field=f.id) "
            "where h.field > 12 and h.message=$1 order by h.part ",
            this
        );
        d->hf->bind( 1, d->messageId );
        d->hf->execute();
    }

    while ( d->hf->hasResults() ) {
        Row * r = d->hf->nextRow();

        String part = r->getString( "part" );
        String name = r->getString( "name" );
        UString value = r->getUString( "value" );

        Header * h = d->message->header();
        if ( part.endsWith( ".rfc822" ) ) {
            Bodypart * bp =
                d->message->bodypart( part.mid( 0, part.length()-7 ), true );
            if ( !bp->message() ) {
                bp->setMessage( new Message );
                bp->message()->setParent( bp );
            }
            h = bp->message()->header();
        }
        else if ( !part.isEmpty() ) {
            h = d->message->bodypart( part, true )->header();
        }
        HeaderField * f = HeaderField::assemble( name, value );
        f->setPosition( r->getInt( "position" ) );
        h->add( f );
    }

    if ( !d->af ) {
        if ( !d->hf->done() )
            return;

        d->af = new Query(
            "select af.part, af.position, af.field, af.number, "
            "a.name, a.localpart, a.domain from "
            "address_fields af join addresses a on (af.address=a.id) "
            "where af.message=$1 order by af.part, af.field, af.number ",
            this
        );
        d->af->bind( 1, d->messageId );
        d->af->execute();
    }

    while ( d->af->hasResults() ) {
        Row * r = d->af->nextRow();

        if ( r->isNull( "number" ) ) {
            // XXX: We should fallback to old-school address fetching here.
        }

        String part = r->getString( "part" );
        uint position = r->getInt( "position" );
        HeaderField::Type field = (HeaderField::Type)r->getInt( "field" );

        Header * h = d->message->header();
        if ( part.endsWith( ".rfc822" ) ) {
            Bodypart * bp =
                d->message->bodypart( part.mid( 0, part.length()-7 ), true );
            if ( !bp->message() ) {
                bp->setMessage( new Message );
                bp->message()->setParent( bp );
            }
            h = bp->message()->header();
        }
        else if ( !part.isEmpty() ) {
            h = d->message->bodypart( part, true )->header();
        }
        AddressField * f = 0;
        uint n = 0;
        f = (AddressField*)h->field( field, 0 );
        while ( f && f->position() < position ) {
            n++;
            f = (AddressField*)h->field( field, n );
        }
        if ( !f || f->position() > position ) {
            f = new AddressField( field );
            f->setPosition( position );
            h->add( f );
        }
        Utf8Codec u;
        Address * a = new Address( r->getUString( "name" ),
                                   r->getString( "localpart" ),
                                   r->getString( "domain" ) );
        f->addresses()->append( a );
    }

    if ( !d->bf ) {
        if ( !d->af->done() )
            return;

        d->bf = new Query(
            "select p.part,b.text,b.data,b.bytes as rawbytes,p.bytes,p.lines "
            "from part_numbers p left join bodyparts b on (p.bodypart=b.id) "
            "where p.message=$1 and p.part != '' order by p.part",
            this
        );
        d->bf->bind( 1, d->messageId );
        d->bf->execute();
    }

    while ( d->bf->hasResults() ) {
        Row * r = d->bf->nextRow();

        String part = r->getString( "part" );

        if ( part.endsWith( ".rfc822" ) ) {
            Bodypart *bp =
                d->message->bodypart( part.mid( 0, part.length()-7 ), true );
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
            Bodypart * bp = d->message->bodypart( part, true );

            if ( !r->isNull( "data" ) )
                bp->setData( r->getString( "data" ) );
            else if ( !r->isNull( "text" ) )
                bp->setText( r->getUString( "text" ) );

            if ( !r->isNull( "rawbytes" ) )
                bp->setNumBytes( r->getInt( "rawbytes" ) );
            if ( !r->isNull( "bytes" ) )
                bp->setNumEncodedBytes( r->getInt( "bytes" ) );
            if ( !r->isNull( "lines" ) )
                bp->setNumEncodedLines( r->getInt( "lines" ) );
        }
    }

    if ( !d->message->hasHeaders() ) {
        if ( !d->bf->done() )
            return;

        d->message->setHeadersFetched();
        d->message->setAddressesFetched();
        d->message->setBodiesFetched();
        d->owner->execute();
    }
}
