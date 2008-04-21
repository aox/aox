#include "fetcher.h"

#include "addressfield.h"
#include "transaction.h"
#include "messageset.h"
#include "annotation.h"
#include "allocator.h"
#include "bodypart.h"
#include "mailbox.h"
#include "message.h"
#include "session.h"
#include "ustring.h"
#include "query.h"
#include "scope.h"
#include "flag.h"
#include "utf.h"


class FetcherData
    : public Garbage
{
public:
    FetcherData()
        : owner( 0 ),
          mailbox( 0 ),
          q( 0 ), t( 0 ),
          flags( false ), annotations( false ),
          addresses( false ), otherheader( false ),
          body( false ), trivia( false ),
          partnumbers( false ),
          f( 0 )
    {}

    List<Message> messages;
    EventHandler * owner;
    Mailbox * mailbox;
    List<Query> * q;
    Transaction * t;

    bool flags;
    bool annotations;
    bool addresses;
    bool otherheader;
    bool body;
    bool trivia;
    bool partnumbers;

    Fetcher * f;

    class Decoder
        : public EventHandler
    {
    public:
        Decoder(): q( 0 ), d( 0 ), a( 0 ) {}
        void execute();
        void shift();
        virtual void decode( Message *, Row * ) = 0;
        virtual void setDone( Message * ) = 0;
        Query * q;
        FetcherData * d;
        List<Message> messages;
        uint a;
    };

    Query * decoder( const String & s, Decoder * d ) {
        Query * q = new Query( s, d );
        d->d = this;
        d->q = q; // d->q is Decoder::q, not FetcherData::q. evil.
        List<Message>::Iterator m( messages );
        while ( m ) {
            d->messages.append( m );
            ++m;
        }
        return q;
    }

    class FlagsDecoder
        : public Decoder
    {
    public:
        FlagsDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class TriviaDecoder
        : public Decoder
    {
    public:
        TriviaDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class AnnotationDecoder
        : public Decoder
    {
    public:
        AnnotationDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class AddressDecoder
        : public Decoder
    {
    public:
        AddressDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class HeaderDecoder
        : public Decoder
    {
    public:
        HeaderDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class PartNumberDecoder
        : public Decoder
    {
    public:
        PartNumberDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class BodyDecoder
        : public PartNumberDecoder
    {
    public:
        BodyDecoder() {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };
};


static String queryText( Fetcher::Type t,
                         const String & source,
                         const String & cursorName )
{
    String r;
    if ( cursorName.isEmpty() ) {
        // no cursor
    }
    else {
        r.append( "declare " );
        r.append( cursorName );
        r.append( " no scroll cursor for " );
    }

    switch ( t ) {
    case Fetcher::Flags:
        // this is suboptimal in the common case. it doesn't need to
        // join. we could look for the most common variant of source
        // and select a simpler query.
        r.append( "select f.uid, f.flag from flags f "
                  "join " );
        r.append( source );
        r.append( " m using (mailbox,uid)" );
        break;
    case Fetcher::Annotations:
        r.append( "select a.uid, a.owner, a.value, an.name, an.id "
                  "from annotations a "
                  "join annotation_names an on (a.name=an.id) "
                  "join " );
        r.append( source );
        r.append( " m using (mailbox,uid)" );
        break;
    case Fetcher::Addresses:
        r.append( "select m.uid, af.part, af.position, af.field, af.number, "
                  "a.name, a.localpart, a.domain from " );
        r.append( source );
        r.append( " m join address_fields af using (message) "
                  "join addresses a on (af.address=a.id) "
                  "order by m.uid, af.part, af.field, af.number " );
        break;
    case Fetcher::OtherHeader:
        r.append( "select m.uid, h.part, h.position, f.name, h.value from " );
        r.append( source );
        r.append( " m join header_fields h using (message) "
                  "join field_names f on (h.field=f.id) "
                  "order by m.uid, h.part" );
        break;
    case Fetcher::Body:
        // this implicitly also fetches PartNumbers, below...
        r.append( "select m.uid, p.part, b.text, b.data, "
                  "b.bytes as rawbytes, p.bytes, p.lines "
                  "from " );
        r.append( source );
        r.append( " m join part_numbers p using (message) "
                  "left join bodyparts b on (p.bodypart=b.id) "
                  "where b.id is not null "
                  "order by m.uid, p.part" );
        break;
    case Fetcher::PartNumbers:
        //... but PartNumbers is available on its own for more speed
        r.append( "select m.uid, p.part, p.bytes, p.lines "
                  "from " );
        r.append( source );
        r.append( " m join part_numbers p using (message) "
                  "order by m.uid, p.part" );
        break;
    case Fetcher::Trivia:
        if ( source.startsWith( "(select mailbox, message, uid "
                                "from mailbox_messages "
                                "where mailbox=$1 and " ) ) {
            // what an amazingly evil hack this is. I want to do it cleaner
            // when the new fetcher is a little more cooked.
            r.append( "select m.id, mm.uid, mm.idate, m.rfc822size, mm.modseq "
                      "from messages m "
                      "join mailbox_messages mm on (mm.message=m.id) "
                      "where " );
            r.append( source
                      .mid( 0, source.length()-1 )
                      .section( " where ", 2 ) );
            r.append( " order by mm.uid" );
        }
        else {
            // and this isn't too pretty either.
            r.append( "select m.id, m2.uid, mm.idate, m.rfc822size, mm.modseq "
                      "from " );
            r.append( source );
            r.append( " m2 join mailbox_messages mm using (mailbox,uid) "
                      "join messages m on (m2.mailbox=m.id) "
                      "order by mm.uid" );
        }
        break;
    }
    return r;
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
    setLog( new Log( Log::Database ) );
    d->mailbox = m;
    d->owner = e;
    d->f = this;
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
    if ( d->t && !d->t->done() )
        return false;
    if ( d->q ) {
        List<Query>::Iterator i( d->q );
        while ( i ) {
            if ( !i->done() )
                return false;
            ++i;
        }
    }
    return true;
}


/*! A fairly complex function. Since fetching messages is one of the
    primary activities of Archiveopteryx and this function does it,
    some complexity is warranted, I think.
    
    The function creates up to six queries that return data, and may
    create a transaction and other queries in support of the six.
*/

void Fetcher::execute()
{
    Scope x( log() );
    if ( d->t ) {
        // this will need updating as soon as we issue smaller
        // fetches. it will become regrettably complex.
        if ( d->t->done() )
            d->owner->execute();
        return;
    }
    else if ( d->q ) {
        if ( done() )
            d->owner->execute();
        return;
    }

    bool simple = false;

    StringList what;
    what.append( new String( "Data type(s): " ) );
    uint n = 0;
    if ( d->flags ) {
        n++;
        what.append( "flags" );
    }
    if ( d->annotations ) {
        n++;
        what.append( "annotations" );
    }
    if ( d->addresses ) {
        n++;
        what.append( "addresses" );
    }
    if ( d->otherheader ) {
        n++;
        what.append( "otherheader" );
    }
    if ( d->body ) {
        n++;
        what.append( "body" );
    }
    if ( d->trivia ) {
        n++;
        what.append( "trivia" );
    }
    if ( d->partnumbers && !d->body ) {
        n++;
        what.append( "bytes/lines" );
    }
    if ( n < 1 ) {
        // nothing to do.
        return;
    }
    
    log( "Fetching data for " + fn( d->messages.count() ) + " messages. " +
         what.join( " " ) );

    MessageSet s;
    List<Message>::Iterator i( d->messages );
    while ( i ) {
        s.add( i->uid() );
        ++i;
    }
    if ( !s.isRange() && s.count() > 64 ) {
        // if s.where() contains complex boolean logic and more than a
        // few numbers, we'll benefit from simplifying it. so we look
        // for the most recently updated session, and use its UID gaps
        // to simplify s.
        Session * best = 0;
        List<Session>::Iterator it( d->mailbox->sessions() );
        while ( it ) {
            if ( !best || best->nextModSeq() < it->nextModSeq() )
                best = it;
            ++it;
        }
        if ( best )
            s.addGapsFrom( best->messages() );
    }

    if ( n == 1 )
        // it really is simple
        simple = true;
    else if ( s.isRange() && s.count() < 512 && n < 3 )
        // it isn't simple, but it's simple enough that the complexity
        // of using cursors and a transaction doesn't pay for itself.
        // the numbers above need tweaking.
        simple = true;
    
    if ( simple ) {
        // a query or two. or three.
        String t = "(select mailbox, message, uid "
                   "from mailbox_messages "
                   "where mailbox=$1 and " + s.where() + ")";
        d->q = new List<Query>;
        if ( d->flags )
            d->q->append( d->decoder( queryText( Flags, t, "" ),
                                      new FetcherData::FlagsDecoder ) );
        if ( d->trivia )
            d->q->append( d->decoder( queryText( Trivia, t, "" ),
                                      new FetcherData::TriviaDecoder ) );
        if ( d->annotations )
            d->q->append( d->decoder( queryText( Annotations, t, "" ),
                                      new FetcherData::AnnotationDecoder ) );
        if ( d->addresses )
            d->q->append( d->decoder( queryText( Addresses, t, "" ),
                                      new FetcherData::AddressDecoder ) );
        if ( d->otherheader )
            d->q->append( d->decoder( queryText( OtherHeader, t, "" ),
                                      new FetcherData::HeaderDecoder ) );
        if ( d->body )
            d->q->append( d->decoder( queryText( Body, t, "" ),
                                      new FetcherData::BodyDecoder ) );
        if ( d->partnumbers && !d->body )
            d->q->append( d->decoder( queryText( PartNumbers, t, "" ),
                                      new FetcherData::PartNumberDecoder ) );
        List<Query>::Iterator i( d->q );
        while ( i ) {
            i->bind( 1, d->mailbox->id() );
            i->execute();
            ++i;
        }
    }
    else {
        d->t = new Transaction( this );
        Query * q
            = new Query( "create temporary table matching_messages ("
                         "mailbox integer, "
                         "uid integer, "
                         "message integer"
                         ") on commit drop",
                         0 );
        d->t->enqueue( q );
        q = new Query( "insert into matching_messages (mailbox, message, uid) "
                       "select mailbox, message, uid "
                       "from mailbox_messages "
                       "where mailbox=$1 and " + s.where(),
                       0 );
        q->bind( 1, d->mailbox->id() );
        d->t->enqueue( q );
        const char * f = "matching_messages";
        if ( d->flags )
            d->t->enqueue( new Query( queryText( Flags, f, "fc" ),
                                      0 ) );
        if ( d->trivia )
            d->t->enqueue( new Query( queryText( Trivia, f, "tc" ),
                                      0 ) );
        if ( d->annotations )
            d->t->enqueue( new Query( queryText( Annotations, f, "ac" ),
                                      0 ) );
        if ( d->addresses )
            d->t->enqueue( new Query( queryText( Addresses, f, "afc" ),
                                      0 ) );
        if ( d->otherheader )
            d->t->enqueue( new Query( queryText( OtherHeader, f, "hfc" ),
                                      0 ) );
        if ( d->body )
            d->t->enqueue( new Query( queryText( Body, f, "bc" ),
                                      0 ) );
        if ( d->partnumbers && !d->body )
            d->t->enqueue( new Query( queryText( PartNumbers, f, "bc" ),
                                      0 ) );

        // strictly speaking we need to fetch about 1000-10000 rows at
        // a time from each cursor, always taking the one that has
        // progressed shortest. that way we can start issuing
        // responses before we have all the messages in RAM.

        // but I don't want to implement that yet. I want to get
        // something up and running, and then optimise for lower
        // memory usage.

        // so I just append a few fetches here. (as is appropriate
        // anyway if we're fetching fewish messages.)

        if ( d->flags )
            d->t->enqueue( d->decoder( "fetch all from fc",
                                       new FetcherData::FlagsDecoder ) );
        if ( d->trivia )
            d->t->enqueue( d->decoder( "fetch all from tc",
                                       new FetcherData::TriviaDecoder ) );
        if ( d->annotations )
            d->t->enqueue( d->decoder( "fetch all from ac",
                                       new FetcherData::AnnotationDecoder ) );
        if ( d->addresses )
            d->t->enqueue( d->decoder( "fetch all from afc",
                                       new FetcherData::AddressDecoder ) );
        if ( d->otherheader )
            d->t->enqueue( d->decoder( "fetch all from hfc",
                                       new FetcherData::HeaderDecoder ) );
        if ( d->body )
            d->t->enqueue( d->decoder( "fetch all from bc",
                                       new FetcherData::BodyDecoder ) );
        if ( d->partnumbers && !d->body )
            d->t->enqueue( d->decoder( "fetch all from bc",
                                       new FetcherData::PartNumberDecoder ) );
        d->t->commit();
    }
}


void FetcherData::Decoder::execute()
{
    Message * m = 0;
    uint uid = 0;
    Row * r = q->nextRow();
    while ( r ) {
        uint u = r->getInt( "uid" );
        if ( u != uid || !m ) {
            uid = u;
            m = 0;
            while ( !messages.isEmpty() &&
                    messages.firstElement()->uid() < uid ) {
                setDone( messages.firstElement() );
                shift();
            }
            if ( !messages.isEmpty() )
                m = messages.firstElement();
        }
        if ( m )
            decode( m, r );
        r = q->nextRow();
    }
    if ( !q->done() )
        return;

    // this has to move into Fetcher::execute() when we learn to fetch
    // in smaller chunks.
    while ( !messages.isEmpty() ) {
        setDone( messages.firstElement() );
        shift();
    }
    d->f->execute();
}



void FetcherData::Decoder::shift()
{
    messages.shift();    
    a++;
    if ( a < 128 && !messages.isEmpty() )
        return;
    a = 0;
    log( "Have fetched until " + ( messages.isEmpty() 
                                   ? "the end"
                                   : fn( messages.firstElement()->uid() ) ) );
    // if !messages.isEmpty() and a special flags is set: return.  and
    // set that flag for all but the presumably slowest/last fetcher.
    if ( d->owner )
        d->owner->execute();
}


void FetcherData::HeaderDecoder::decode( Message * m, Row * r )
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


void FetcherData::HeaderDecoder::setDone( Message * m )
{
    m->setHeadersFetched();
}



void FetcherData::AddressDecoder::decode( Message * m, Row * r )
{
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
    }
    // we could save a bit of memory here if we keep a data structure
    // in the decoder, so every address with ID 4321432 becomes a
    // pointer to the same address, at least within the same
    // fetch. hm.
    Utf8Codec u;
    Address * a = new Address( r->getUString( "name" ),
                               r->getString( "localpart" ),
                               r->getString( "domain" ) );
    f->addresses()->append( a );
}


void FetcherData::AddressDecoder::setDone( Message * m )
{
    m->setAddressesFetched();
}


void FetcherData::FlagsDecoder::decode( Message * m, Row * r )
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
        // announce it in the select response, either.
    }
}


void FetcherData::FlagsDecoder::setDone( Message * m )
{
    m->setFlagsFetched( true );

}


void FetcherData::BodyDecoder::decode( Message * m, Row * r )
{
    PartNumberDecoder::decode( m, r );

    String part = r->getString( "part" );

    if ( !part.endsWith( ".rfc822" ) ) {
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


void FetcherData::BodyDecoder::setDone( Message * m )
{
    m->setBodiesFetched();
    m->setBytesAndLinesFetched();
}


void FetcherData::PartNumberDecoder::decode( Message * m, Row * r )
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

        if ( !r->isNull( "bytes" ) )
            bp->setNumEncodedBytes( r->getInt( "bytes" ) );
        if ( !r->isNull( "lines" ) )
            bp->setNumEncodedLines( r->getInt( "lines" ) );
    }

        
}


void FetcherData::PartNumberDecoder::setDone( Message * m )
{
    m->setBytesAndLinesFetched();
}


void FetcherData::TriviaDecoder::decode( Message * m , Row * r )
{
    m->setInternalDate( r->getInt( "idate" ) );
    m->setRfc822Size( r->getInt( "rfc822size" ) );
    if ( !r->isNull( "modseq" ) )
        m->setModSeq( r->getBigint( "modseq" ) );
}


void FetcherData::TriviaDecoder::setDone( Message * )
{
    // hard work ;-)
}


void FetcherData::AnnotationDecoder::decode( Message * m, Row * r )
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


void FetcherData::AnnotationDecoder::setDone( Message * m )
{
    m->setAnnotationsFetched();
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

    This class can be rewritten to use the new Fetcher fairly easily.
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


/*! Instructs this Fetcher to fetch data of type \a t. */

void Fetcher::fetch( Type t )
{
    switch ( t ) {
    case Flags:
        d->flags = true;
        break;
    case Annotations:
        d->annotations = true;
        break;
    case Addresses:
        d->addresses = true;
        break;
    case OtherHeader:
        d->otherheader = true;
        break;
    case Body:
        d->body = true;
        d->partnumbers = true; // implicitly
        break;
    case Trivia:
        d->trivia = true;
        break;
    case PartNumbers:
        d->partnumbers = true;
        break;
    }
}


/*! Returns true if this Fetcher will fetch (or is fetching) data of
    type \a t. Returns false until fetch() has been called for \a t.
*/

bool Fetcher::fetching( Type t ) const
{
    switch ( t ) {
    case Flags:
        return d->flags;
        break;
    case Annotations:
        return d->annotations;
        break;
    case Addresses:
        return d->addresses;
        break;
    case OtherHeader:
        return d->otherheader;
        break;
    case Body:
        return d->body;
        break;
    case Trivia:
        return d->trivia;
        break;
    case PartNumbers:
        return d->partnumbers;
        break;
    }
    return false; // not reached
}
