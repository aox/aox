// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "fetcher.h"

#include "addressfield.h"
#include "transaction.h"
#include "integerset.h"
#include "allocator.h"
#include "bodypart.h"
#include "selector.h"
#include "postgres.h"
#include "mailbox.h"
#include "message.h"
#include "ustring.h"
#include "buffer.h"
#include "query.h"
#include "scope.h"
#include "timer.h"
#include "utf.h"
#include "map.h"

#include <time.h> // time()


enum State { NotStarted, Fetching, Done };


class FetcherData
    : public Garbage
{
public:
    FetcherData()
        : owner( 0 ),
          q( 0 ),
          transaction( 0 ),
          f( 0 ),
          state( NotStarted ),
          maxBatchSize( 32768 ),
          batchSize( 0 ),
          uniqueDatabaseIds( true ),
          lastBatchStarted( 0 ),
          addresses( 0 ), otherheader( 0 ),
          body( 0 ), trivia( 0 ),
          partnumbers( 0 ),
          throttler( 0 )
    {}

    List<Message> messages;
    Map< List<Message> > batch;
    EventHandler * owner;
    List<Query> * q;
    Transaction * transaction;

    Fetcher * f;
    State state;
    uint maxBatchSize;
    uint batchSize;
    bool uniqueDatabaseIds;
    uint lastBatchStarted;

    class Decoder
        : public EventHandler
    {
    public:
        Decoder( FetcherData * fd )
            : q( 0 ), d( fd ) {
            setLog( new Log );
        }
        void execute();
        void process();
        virtual void decode( Message *, List<Row> * ) = 0;
        virtual void setDone( Message * ) = 0;
        virtual bool isDone( Message * ) const = 0;
        Query * q;
        FetcherData * d;
        List<Row> mr;
    };

    Decoder * addresses;
    Decoder * otherheader;
    Decoder * body;
    Decoder * trivia;
    Decoder * partnumbers;

    class TriviaDecoder
        : public Decoder
    {
    public:
        TriviaDecoder( FetcherData * fd )
            : Decoder( fd ) {}
        void decode( Message *, List<Row> * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class AddressDecoder
        : public Decoder
    {
    public:
        AddressDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, List<Row> * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class HeaderDecoder
        : public Decoder
    {
    public:
        HeaderDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, List<Row> * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class PartNumberDecoder
        : public Decoder
    {
    public:
        PartNumberDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, List<Row> * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class BodyDecoder
        : public PartNumberDecoder
    {
    public:
        BodyDecoder( FetcherData * fd ): PartNumberDecoder( fd ) {}
        void decode( Message *, List<Row> * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    Buffer * throttler;
};


/*! \class Fetcher fetcher.h

    The Fetcher class retrieves Message data for some/all messages in
    a Mailbox. It's a management class to do Message and Mailbox
    aspects of the job; internal classes provide the Query or
    PreparedStatement objects necessary to fetch specific data.

    A Fetcher lives for a while, fetching data about a range of
    messages. Whenever it finishes its current retrieval, it finds the
    largest range of messages currently needing retrieval, and issues
    an SQL select for them. Typically the select ends with
    "mailbox=$71 and uid in any($72). When the Fetcher isn't useful
    any more, its owner drops it on the floor.
*/


/*! Constructs an empty Fetcher which will fetch \a messages and
    notify \a e when it's done, taking care to keep \a buffer short. */

Fetcher::Fetcher( List<Message> * messages, EventHandler * e,
                  Buffer * buffer )
    : EventHandler(), d( new FetcherData )
{
    setLog( new Log );
    d->owner = e;
    d->f = this;
    d->throttler = buffer;
    addMessages( messages );
}


/*! Constructs a Fetcher which will fetch the single message \a m by
    Message::databaseId() and notify \a owner when it's done.

    The constructed Fetcher can only fetch bodies, headers and
    addresses.
*/

Fetcher::Fetcher( Message * m, EventHandler * owner )
    : EventHandler(), d( new FetcherData )
{
    setLog( new Log );
    d->owner = owner;
    d->f = this;
    d->messages.append( m );
}


/*! Adds \a message to the list of messages fetched. This does not
    re-execute the fetcher - the user must execute() it if done().
*/

void Fetcher::addMessage( Message * message )
{
    if ( message )
        d->messages.append( message );
}


/*! Adds \a messages to the list of messages fetched. This does not
    re-execute the fetcher - the user must execute() it if done(). */

void Fetcher::addMessages( List<Message> * messages )
{
    Scope x( log() );
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
    if ( d->state == Done )
        return true;
    return false;
}


void Fetcher::execute()
{
    Scope x( log() );
    State s = d->state;
    do {
        s = d->state;
        switch ( d->state )
        {
        case NotStarted:
            start();
            break;
        case Fetching:
            waitForEnd();
            break;
        case Done:
            break;
        }
    } while ( s != d->state );
}


/*! Decides whether to issue a number of parallel SQL selects or to
    use a two-stage process with a complex intermediate data
    structure. The decision is based on entirely heuristic factors.

    This function knows something about how many messages we want, but
    it doesn't know how many we'll get. The two numbers are equal in
    practice.
*/


void Fetcher::start()
{
    EStringList what;
    what.append( new EString( "Data type(s): " ) );
    uint n = 0;
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
        d->partnumbers = 0;
    }
    if ( d->trivia ) {
        n++;
        what.append( "trivia" );
    }
    if ( d->partnumbers && !d->body ) {
        n++;
        what.append( "bytes/lines" );
    }

    if ( n < 1 || d->messages.isEmpty() ) {
        // nothing to do.
        d->state = Done;
        return;
    }

    log( "Fetching data for " + fn( d->messages.count() ) + " messages. " +
         what.join( " " ) );

    // we'll use two steps. first, we find a good size for the first
    // batch.
    d->batchSize = 4096;
    if ( d->body )
        d->batchSize = d->batchSize / 2;
    if ( d->otherheader )
        d->batchSize = d->batchSize * 2 / 3;
    if ( d->addresses )
        d->batchSize = d->batchSize * 3 / 4;
    if ( Postgres::version() < 80200 && d->batchSize > 50 && d->otherheader )
        d->batchSize = 50;

    d->state = Fetching;
    prepareBatch();
    makeQueries();
}


/*! Checks whether all queries and decoders are done. When the
    decoders are, then the Fetcher may or may not be. Perhaps it's
    time to start another batch, perhaps it's time to notify the
    owner.
*/


void Fetcher::waitForEnd()
{
    List<FetcherData::Decoder> decoders;
    if ( d->addresses )
        decoders.append( d->addresses );
    if ( d->otherheader )
        decoders.append( d->otherheader );
    if ( d->body )
        decoders.append( d->body );
    if ( d->trivia )
        decoders.append( d->trivia );
    if ( d->partnumbers )
        decoders.append( d->partnumbers );

    List<FetcherData::Decoder>::Iterator i( decoders );
    while ( i ) {
        if ( i->q && !i->q->done() )
            return;
        ++i;
    }

    Map< List<Message> >::Iterator bi( d->batch );
    while ( bi ) {
        List<Message>::Iterator li( *bi );
        ++bi;
        while ( li ) {
            Message * m = li;
            ++li;

            List<FetcherData::Decoder>::Iterator di( decoders );
            while ( di ) {
                di->setDone( m );
                ++di;
            }
        }
    }

    if ( d->messages.isEmpty() ) {
        d->state = Done;
        if ( d->transaction )
            d->transaction->commit();
    }
    else if ( d->throttler && d->throttler->size() > 1024*1024 ) {
        (void)new Timer( this, 2 );
    }
    else {
        prepareBatch();
        makeQueries();
    }
    if ( d->owner )
        d->owner->notify();
}


/*! Messages are fetched in batches, so that we can deliver some rows
    early on. This function adjusts the size of the batches so we'll
    get about one batch every 6 seconds, and updates the tables so we
    have a batch ready for reading.
*/


void Fetcher::prepareBatch()
{
    uint now = (uint)time( 0 );
    if ( d->lastBatchStarted ) {
        uint prevBatchSize = d->batchSize;
        if ( now == d->lastBatchStarted ) {
            // if we took zero time, let's do a small batch size
            // increase, because that's suspiciously fast.
            d->batchSize = d->batchSize * 2;
        }
        else if ( now < d->lastBatchStarted ) {
            // if time went backwards we're very, very careful.
            d->batchSize = 128;
        }
        else {
            // we adjust the batch size so the next batch could take
            // something in the approximate region of 6 seconds.
            uint diff = now - d->lastBatchStarted;
            d->batchSize = d->batchSize * 6 / diff;
        }

        // the batch size can't increase too much
        if ( d->batchSize > prevBatchSize * 3 )
            d->batchSize = prevBatchSize * 3;
        if ( d->batchSize > prevBatchSize + 2000 )
            d->batchSize = prevBatchSize + 2000;

        // and we generally don't want it to be too large or small
        if ( d->batchSize < 128 )
            d->batchSize = 128;
        if ( d->batchSize > d->maxBatchSize )
            d->batchSize = d->maxBatchSize;

        // if we're memory-constrained, then we adjust the batch size
        // to the amount of RAM we'll probably use. the amount of RAM
        // we use per message is higher if we'll issue all queries in
        // sequence, lower if we issue them in parallel. both 40k and
        // 80k are dreadful estimates, some messages are many-megabyte
        // monsters, others just 4k.
        uint limit = 1024 * 1024 *
                     Configuration::scalar( Configuration::MemoryLimit );
        uint already = Allocator::inUse() + Allocator::allocated();
        uint perMessage = 40 * 1024;
        if ( d->transaction || Database::numHandles() < 2 )
            perMessage = 80 * 1024;
        uint batchSizeLimit = ( limit - already ) / perMessage;
        if ( batchSizeLimit < 32 )
            batchSizeLimit = 32; // just sanity, shouldn't actually hit
        if ( d->batchSize > batchSizeLimit )
            d->batchSize = batchSizeLimit;

        // finally, if pg is old enough to misplan =any(...) and the
        // often-misplanned query would be run, then we keep the batch
        // size properly down
        if ( Postgres::version() < 80200 &&
             d->batchSize > 50 &&
             d->otherheader )
            d->batchSize = 50;

        if ( prevBatchSize != d->batchSize )
            log( "Batch time was " + fn ( now - d->lastBatchStarted ) +
                 " for " + fn( prevBatchSize ) + " messages, adjusting to " +
                 fn( d->batchSize ), Log::Debug );
    }
    d->lastBatchStarted = now;

    // Find out which messages we're going to fetch, and fill in the
    // batch array so we can tie responses to the Message objects.
    d->uniqueDatabaseIds = true;
    d->batch.clear();
    uint n = 0;
    while ( !d->messages.isEmpty() && n < d->batchSize ) {
        Message * m = d->messages.shift();
        List<Message> * l = d->batch.find( m->databaseId() );
        if ( !l ) {
            l = new List<Message>;
            d->batch.insert( m->databaseId(), l );
        }
        l->append( m );
        n++;
    }
}




/*! Finds out which messages need information of \a type, and binds a
    list of their database IDs to parameter \a n of \a query.
*/

void Fetcher::bindIds( Query * query, uint n, Type type )
{
    IntegerSet l;
    Map< List<Message> >::Iterator bi( d->batch );
    while ( bi ) {
        List<Message>::Iterator li( *bi );
        ++bi;
        while ( li ) {
            Message * m = li;
            ++li;
            bool need = true;
            switch ( type ) {
            case Addresses:
                if ( m->hasAddresses() )
                    need = false;
                break;
            case OtherHeader:
                if ( m->hasHeaders() )
                    need = false;
                break;
            case Body:
                if ( m->hasBodies() )
                    need = false;
                break;
            case PartNumbers:
                if ( m->hasBytesAndLines() )
                    need = false;
                break;
            case Trivia:
                if ( m->hasTrivia() )
                    need = false;
                break;
            }
            if ( need && m->databaseId() )
                l.add( m->databaseId() );
        }
    }
    query->bind( n, l );
}


/*! Issues the necessary selects to retrieve data and feed the
    decoders. This function does some optimisation of the generated
    SQL.
*/

void Fetcher::makeQueries()
{
    EStringList wanted;
    wanted.append( "mailbox" );
    wanted.append( "uid" );
    wanted.append( "message" );

    Query * q = 0;
    EString r;

    if ( d->partnumbers && !d->body ) {
        // body (below) will handle this as a side effect
        q = new Query( "select message, part, bytes, lines "
                       "from part_numbers where message=any($1) "
                       "order by message, part",
                       d->partnumbers );
        bindIds( q, 1, PartNumbers );
        submit( q );
        d->partnumbers->q = q;
    }

    if ( d->trivia ) {
        // don't need to order this - just one row per message
        q = new Query( "select id as message, idate, rfc822size "
                       "from messages where id=any($1)", d->trivia );
        bindIds( q, 1, Trivia );
        submit( q );
        d->trivia->q = q;
    }

    if ( d->addresses ) {
        q = new Query( "select af.message, "
                       "af.part, af.position, af.field, af.number, "
                       "a.name, a.localpart, a.domain "
                       "from address_fields af "
                       "join addresses a on (af.address=a.id) "
                       "where af.message=any($1) "
                       "order by af.message, af.part, af.field, af.number",
                       d->addresses );
        bindIds( q, 1, Addresses );
        submit( q );
        d->addresses->q = q;
    }

    if ( d->otherheader ) {
        q = new Query( "select hf.message, hf.part, hf.position, "
                       "fn.name, hf.value from header_fields hf "
                       "join field_names fn on (hf.field=fn.id) "
                       "where hf.message=any($1) "
                       "order by hf.message, hf.part",
                       d->otherheader );
        bindIds( q, 1, OtherHeader );
        submit( q );
        d->otherheader->q = q;
    }

    if ( d->body ) {
        q = new Query( "select pn.message, pn.part, bp.text, bp.data, "
                       "bp.bytes as rawbytes, pn.bytes, pn.lines "
                       "from part_numbers pn "
                       "left join bodyparts bp on (pn.bodypart=bp.id) "
                       "where pn.message=any($1) "
                       "order by pn.message, pn.part",
                       d->body );
        bindIds( q, 1, Body );
        submit( q );
        d->body->q = q;
    }

    if ( d->transaction )
        d->transaction->execute();
}


void FetcherData::Decoder::execute()
{
    Scope x( log() );
    int mid = 0;
    if ( !mr.isEmpty() )
        mid = mr.firstElement()->getInt( "message" );
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        int id = r->getInt( "message" );
        if ( mid != id ) {
            process();
            mid = id;
        }
        mr.append( r );
    }
    if ( !q->done() )
        return;
    process();
    d->f->execute();
}

void FetcherData::Decoder::process()
{
    if ( mr.isEmpty() )
        return;
    uint id = mr.firstElement()->getInt( "message" );
    List<Message> * l = d->batch.find( id );
    if ( !l )
        return;
    List<Message>::Iterator i( l );
    while ( i ) {
        Message * m = i;
        ++i;
        if ( m && !isDone( m ) ) {
            decode( m, &mr );
            setDone( m );
        }
    }
    mr.clear();
}

void FetcherData::HeaderDecoder::decode( Message * m, List<Row> * rows )
{
    List<Row>::Iterator i( rows );
    while ( i ) {
        Row * r = i;
        ++i;

        EString part = r->getEString( "part" );
        EString name = r->getEString( "name" );
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
            (void)m->bodypart( part.mid( 0, part.length()-7 ) + ".1" );
        }
        else if ( part.isEmpty() ) {
            (void)m->bodypart( "1" );
        }
        else {
            h = m->bodypart( part, true )->header();
        }
        HeaderField * f = HeaderField::assemble( name, value );
        f->setPosition( r->getInt( "position" ) );
        h->add( f );
    }
}


void FetcherData::HeaderDecoder::setDone( Message * m )
{
    m->setHeadersFetched();
}


bool FetcherData::HeaderDecoder::isDone( Message * m ) const
{
    return m->hasHeaders();
}



void FetcherData::AddressDecoder::decode( Message * m, List<Row> * rows )
{
    List<Row>::Iterator i( rows );
    while ( i ) {
        Row * r = i;
        ++i;

        EString part = r->getEString( "part" );
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
                                   r->getEString( "localpart" ),
                                   r->getEString( "domain" ) );
        f->addresses()->append( a );
    }
}


void FetcherData::AddressDecoder::setDone( Message * m )
{
    m->setAddressesFetched();
}


bool FetcherData::AddressDecoder::isDone( Message * m ) const
{
    return m->hasAddresses();
}


void FetcherData::BodyDecoder::decode( Message * m, List<Row> * rows )
{
    PartNumberDecoder::decode( m, rows );

    List<Row>::Iterator i( rows );
    while ( i ) {
        Row * r = i;
        ++i;

    EString part = r->getEString( "part" );

    if ( !part.endsWith( ".rfc822" ) ) {
        Bodypart * bp = m->bodypart( part, true );

        if ( !r->isNull( "data" ) )
            bp->setData( r->getEString( "data" ) );
        else if ( !r->isNull( "text" ) )
            bp->setText( r->getUString( "text" ) );

        if ( !r->isNull( "rawbytes" ) )
            bp->setNumBytes( r->getInt( "rawbytes" ) );
    }
    }
}


void FetcherData::BodyDecoder::setDone( Message * m )
{
    m->setBodiesFetched();
    m->setBytesAndLinesFetched();
}


bool FetcherData::BodyDecoder::isDone( Message * m ) const
{
    return m->hasBodies() && m->hasBytesAndLines();
}


void FetcherData::PartNumberDecoder::decode( Message * m, List<Row> * rows )
{
    List<Row>::Iterator i( rows );
    while ( i ) {
        Row * r = i;
        ++i;

    EString part = r->getEString( "part" );

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
}


void FetcherData::PartNumberDecoder::setDone( Message * m )
{
    m->setBytesAndLinesFetched();
}


bool FetcherData::PartNumberDecoder::isDone( Message * m ) const
{
    return m->hasBytesAndLines();
}


void FetcherData::TriviaDecoder::decode( Message * m , List<Row> * rows )
{
    m->setInternalDate( rows->firstElement()->getInt( "idate" ) );
    m->setRfc822Size( rows->firstElement()->getInt( "rfc822size" ) );
}


void FetcherData::TriviaDecoder::setDone( Message * m )
{
    m->setTriviaFetched( true );
}


bool FetcherData::TriviaDecoder::isDone( Message * m ) const
{
    return m->hasTrivia();
}


/*! Instructs this Fetcher to fetch data of type \a t. */

void Fetcher::fetch( Type t )
{
    Scope x( log() );
    switch ( t ) {
    case Addresses:
        if ( !d->addresses )
            d->addresses = new FetcherData::AddressDecoder( d );
        break;
    case OtherHeader:
        if ( !d->otherheader )
            d->otherheader = new FetcherData::HeaderDecoder( d );
        break;
    case Body:
        if ( !d->body )
            d->body = new FetcherData::BodyDecoder( d );
        fetch( PartNumbers );
        break;
    case Trivia:
        if ( !d->trivia )
            d->trivia = new FetcherData::TriviaDecoder( d );
        break;
    case PartNumbers:
        if ( !d->partnumbers )
            d->partnumbers = new FetcherData::PartNumberDecoder( d );
        break;
    }
}


/*! Returns true if this Fetcher will fetch (or is fetching) data of
    type \a t. Returns false until fetch() has been called for \a t.
*/

bool Fetcher::fetching( Type t ) const
{
    switch ( t ) {
    case Addresses:
        return d->addresses != 0;
        break;
    case OtherHeader:
        return d->otherheader != 0;
        break;
    case Body:
        return d->body != 0;
        break;
    case Trivia:
        return d->trivia != 0;
        break;
    case PartNumbers:
        return d->partnumbers != 0;
        break;
    }
    return false; // not reached
}


/*! Records that all queries done by this Fetcher should be performed
    within \a t. This can be useful e.g. if some messages may be
    locked by \a t, or if the retrieval is tied to \a t logically.
 */

void Fetcher::setTransaction( class Transaction * t )
{
    Scope x( log() );
    d->transaction = t->subTransaction( this );
}


/*! This internal helper makes sure \a q is executed by the
    database.
*/

void Fetcher::submit( Query * q )
{
    q->allowSlowness();
    if ( d->transaction )
        d->transaction->enqueue( q );
    else
        q->execute();
}
