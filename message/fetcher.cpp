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
static PreparedStatement * viewHeader;
static PreparedStatement * address;
static PreparedStatement * viewAddress;
static PreparedStatement * oldAddress;
static PreparedStatement * viewOldAddress;
static PreparedStatement * trivia;
static PreparedStatement * viewTrivia;
static PreparedStatement * flags;
static PreparedStatement * viewFlags;
static PreparedStatement * body;
static PreparedStatement * viewBody;
static PreparedStatement * anno;
static PreparedStatement * viewAnno;


static void setupPreparedStatements()
{
    if ( ::header )
        return;

    const char * q =
        "select h.uid, h.part, h.position, f.name, h.value from "
        "header_fields h, field_names f where "
        "h.field = f.id and h.field > 12 and "
        "h.uid>=$1 and h.uid<=$2 and h.mailbox=$3 "
        "order by h.uid, h.part";
    ::header = new PreparedStatement( q );
    q = "select vm.uid, h.part, h.position, f.name, h.value from "
        "header_fields h "
        "join field_names f on (h.field=f.id) "
        "join view_messages vm on (vm.source=h.mailbox and vm.suid=h.uid) "
        "where "
        "h.field > 12 and "
        "vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 "
        "order by vm.uid, h.part";
    ::viewHeader = new PreparedStatement( q );

    q = "select a.name, a.localpart, a.domain, "
        "af.uid, af.part, af.position, af.field, af.number "
        "from address_fields af join addresses a on af.address=a.id "
        "where af.uid>=$1 and af.uid<=$2 and af.mailbox=$3 "
        "order by af.uid, af.part, af.field, af.number";
    ::address = new PreparedStatement( q );
    q = "select a.name, a.localpart, a.domain, "
        "vm.uid, af.part, af.position, af.field, af.number "
        "from address_fields af join addresses a on af.address=a.id "
        "join view_messages vm on (vm.source=af.mailbox and vm.suid=af.uid) "
        "where vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 "
        "order by vm.uid, af.part, af.field, af.number";
    ::viewAddress = new PreparedStatement( q );

    q = "select h.uid, h.part, h.position, f.name, h.value from "
        "header_fields h, field_names f where "
        "h.field = f.id and h.field<=12 and "
        "h.uid>=$1 and h.uid<=$2 and h.mailbox=$3 "
        "order by h.uid, h.part";
    ::oldAddress = new PreparedStatement( q );
    q = "select vm.uid, h.part, h.position, f.name, h.value from "
        "header_fields h, field_names f "
        "join view_messages vm on (vm.source=h.mailbox and vm.suid=h.uid) "
        "where "
        "h.field = f.id and h.field<=12 and "
        "vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 "
        "order by vm.uid, h.part";
    ::viewOldAddress = new PreparedStatement( q );

    q = "select m.uid, m.idate, m.rfc822size, ms.modseq from messages m "
        "left join modsequences ms using (mailbox,uid) "
        "where m.uid>=$1 and m.uid<=$2 and m.mailbox=$3 "
        "order by m.uid";
    ::trivia = new PreparedStatement( q );
    q = "select vm.uid, m.idate, m.rfc822size, ms.modseq from messages m "
        "left join modsequences ms using (mailbox,uid) "
        "join view_messages vm on (vm.source=m.mailbox and vm.suid=m.uid) "
        "where vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 "
        "order by vm.uid";
    ::viewTrivia = new PreparedStatement( q );

    q = "select p.uid, p.part, b.text, b.data, "
        "b.bytes as rawbytes, p.bytes, p.lines "
        "from part_numbers p left join bodyparts b on p.bodypart=b.id "
        "where p.uid>=$1 and p.uid<=$2 and p.mailbox=$3 and p.part != '' "
        "order by p.uid, p.part";
    ::body = new PreparedStatement( q );
    q = "select vm.uid, p.part, b.text, b.data, "
        "b.bytes as rawbytes, p.bytes, p.lines "
        "from part_numbers p left join bodyparts b on p.bodypart=b.id "
        "join view_messages vm on (vm.source=p.mailbox and vm.suid=p.uid) "
        "where vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 and p.part != '' "
        "order by vm.uid, p.part";
    ::viewBody = new PreparedStatement( q );

    q = "select uid, flag from flags "
        "where uid>=$1 and uid<=$2 and mailbox=$3 "
        "order by uid, flag";
    ::flags = new PreparedStatement( q );
    q = "select vm.uid, f.flag from flags f "
        "join view_messages vm on (vm.source=f.mailbox and vm.suid=f.uid) "
        "where vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 "
        "order by vm.uid, f.flag";
    ::viewFlags = new PreparedStatement( q );

    q = "select a.uid, a.owner, a.value, an.name, an.id "
        "from annotations a, annotation_names an "
        "where a.uid>=$1 and a.uid<=$2 and a.mailbox=$3 "
        "and a.name=an.id "
        "order by a.uid, an.id, a.owner";
    ::anno = new PreparedStatement( q );
    q = "select vm.uid, a.owner, a.value, an.name, an.id "
        "from annotations a "
        "join annotation_names an on (a.name=an.id) "
        "join view_messages vm on (vm.source=a.mailbox and vm.suid=a.uid) "
        "where vm.uid>=$1 and vm.uid<=$2 and vm.view=$3 "
        "order by vm.uid, an.id, a.owner";
    ::viewAnno = new PreparedStatement( q );

    Allocator::addEternal( header,
                           "statement to fetch headers" );
    Allocator::addEternal( viewHeader,
                           "statement to fetch headers from views" );
    Allocator::addEternal( address,
                           "statement to fetch address fields" );
    Allocator::addEternal( viewAddress,
                           "statement to fetch address fields from views" );
    Allocator::addEternal( oldAddress,
                           "statement to fetch pre-1.13 address fields" );
    Allocator::addEternal( viewOldAddress,
                           "statement to fetch pre-1.13 address fields "
                           "from views" );
    Allocator::addEternal( trivia,
                           "statement to fetch approximately nothing" );
    Allocator::addEternal( viewTrivia,
                           "statement to fetch approximately nothing "
                           "from views" );
    Allocator::addEternal( body,
                           "statement to fetch bodies" );
    Allocator::addEternal( viewBody,
                           "statement to fetch bodies from views" );
    Allocator::addEternal( flags,
                           "statement to fetch flags" );
    Allocator::addEternal( viewFlags,
                           "statement to fetch flags from views" );
    Allocator::addEternal( anno,
                           "statement to fetch annotations" );
    Allocator::addEternal( viewAnno,
                           "statement to fetch annotations from views" );
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
    d->query = new Query( *query( d->mailbox->view() ), this );
    d->query->bind( 1, d->smallest );
    d->query->bind( 2, d->largest );
    d->query->bind( 3, d->mailbox->id() );
    d->query->execute();
}


/*! \fn PreparedStatement * Fetcher::query( bool v ) const

    Returns a prepared statement to fetch the appropriate sort of
    message data for a view (if \a v is true) or ordinary mailbox (if
    \a v is false). The result must demand exactly three Query::bind()
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


PreparedStatement * MessageHeaderFetcher::query( bool v ) const
{
    if ( v )
        return ::viewHeader;
    return ::header;
}


void MessageHeaderFetcher::decode( Message * m, Row * r )
{
    String part = r->getString( "part" );
    String name = r->getString( "name" );
    String value = r->getString( "value" );

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


PreparedStatement * MessageAddressFetcher::query( bool v ) const
{
    if ( v )
        return ::viewAddress;
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
    Address * a = new Address( u.toUnicode( r->getString( "name" ) ),
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


PreparedStatement * MessageFlagFetcher::query( bool v ) const
{
    if ( v )
        return ::viewFlags;
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


PreparedStatement * MessageBodyFetcher::query( bool v ) const
{
    if ( v )
        return ::viewBody;
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


PreparedStatement * MessageTriviaFetcher::query( bool v ) const
{
    if ( v )
        return ::viewTrivia;
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

PreparedStatement * MessageAnnotationFetcher::query( bool v ) const
{
    if ( v )
        return ::viewAnno;
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
    fetches the other header fields. \a v must be true if the mailbox
    concerned is a view and false if not.
*/

PreparedStatement * MessageOldAddressFetcher::query( bool v ) const
{
    if ( v )
        return ::viewOldAddress;
    return ::oldAddress;
}


void MessageOldAddressFetcher::setDone( Message * m )
{
    m->setAddressesFetched();
}
