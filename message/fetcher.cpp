#include "fetcher.h"

#include "addressfield.h"
#include "transaction.h"
#include "messageset.h"
#include "annotation.h"
#include "allocator.h"
#include "bodypart.h"
#include "selector.h"
#include "mailbox.h"
#include "message.h"
#include "session.h"
#include "ustring.h"
#include "query.h"
#include "scope.h"
#include "flag.h"
#include "utf.h"

#include <time.h> // time()


enum State { NotStarted, FindingMessages, Fetching, Done };


class FetcherData
    : public Garbage
{
public:
    FetcherData()
        : owner( 0 ),
          mailbox( 0 ),
          q( 0 ), t( 0 ),
          findMessages( 0 ),
          f( 0 ),
          messageId( 0 ), state( NotStarted ),
          selector( 0 ),
          maxBatchSize( 32768 ),
          batchSize( 128 ),
          usingTableFilled( false ),
          lastBatchStarted( 0 ),
          messagesExpected( 0 ),
          flags( 0 ), annotations( 0 ),
          addresses( 0 ), otherheader( 0 ),
          body( 0 ), trivia( 0 ),
          partnumbers( 0 )
    {}

    List<Message> messages;
    EventHandler * owner;
    Mailbox * mailbox;
    List<Query> * q;
    Transaction * t;
    Query * findMessages;

    Fetcher * f;
    uint messageId;
    State state;
    Selector * selector;
    uint maxBatchSize;
    uint batchSize;
    bool usingTableFilled;
    String tmptable;
    uint lastBatchStarted;
    uint messagesExpected;

    class Decoder
        : public EventHandler
    {
    public:
        Decoder(): q( 0 ), d( 0 ), uid( 0 ) {}
        void execute();
        virtual void decode( Message *, Row * ) = 0;
        virtual void setDone( Message * ) = 0;
        void setDoneUntil( uint );
        Query * q;
        FetcherData * d;
        List<Message> messages;
        uint uid;
    };

    Decoder * flags;
    Decoder * annotations;
    Decoder * addresses;
    Decoder * otherheader;
    Decoder * body;
    Decoder * trivia;
    Decoder * partnumbers;

    class FlagsDecoder
        : public Decoder
    {
    public:
        FlagsDecoder( FetcherData * fd ) { d = fd; }
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class TriviaDecoder
        : public Decoder
    {
    public:
        TriviaDecoder( FetcherData * fd ) { d = fd; }
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class AnnotationDecoder
        : public Decoder
    {
    public:
        AnnotationDecoder( FetcherData * fd ) { d = fd; }
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class AddressDecoder
        : public Decoder
    {
    public:
        AddressDecoder( FetcherData * fd ) { d = fd; }
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class HeaderDecoder
        : public Decoder
    {
    public:
        HeaderDecoder( FetcherData * fd ) { d = fd; }
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class PartNumberDecoder
        : public Decoder
    {
    public:
        PartNumberDecoder( FetcherData * fd ) { d = fd; }
        void decode( Message *, Row * );
        void setDone( Message * );
    };

    class BodyDecoder
        : public PartNumberDecoder
    {
    public:
        BodyDecoder( FetcherData * fd ): PartNumberDecoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
    };
};


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


/*! Constructs a Fetcher which will fetch the single message \a m,
    which is assumed to have ID \a id (that's messages.id in the
    database) and notify \a owner when it's done.

    The constructed Fetcher can only fetch bodies, headers and
    addresses.
*/

Fetcher::Fetcher( uint id, Message * m, EventHandler * owner )
    : EventHandler(), d( new FetcherData )
{
    setLog( new Log( Log::Database ) );
    d->mailbox = 0;
    d->owner = owner;
    d->f = this;
    d->messages.append( m );
    d->messageId = id;
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
    if ( d->state == Done )
        return true;
    return false;
}


void Fetcher::execute()
{
    Scope x( log() );
    log( "execute entered with state " + fn( d->state ) );
    State s = d->state;
    do {
        s = d->state;
        switch ( d->state )
        {
        case NotStarted:
            start();
            break;
        case FindingMessages:
            findMessages();
            break;
        case Fetching:
            waitForEnd();
            break;
        case Done:
            break;
        }
    } while ( s != d->state );
    log( "execute left with state " + fn( d->state ) );
}


static void copyMessageList( FetcherData * d, FetcherData::Decoder * decoder )
{
    if ( !decoder )
        return;

    List<Message>::Iterator m( d->messages );
    while ( m ) {
        decoder->messages.append( m );
        ++m;
    }
}


/*! Decides whether to issue a number of parallel SQL selects or to
    make a transaction and up to two temporary tables. Makes the
    tables if necessary.

    The decision is based on entirely heuristic factors.

    This function knows something about how many messages we want, but
    it doesn't know how many we'll get. The two numbers are equal in
    practice.
*/


void Fetcher::start()
{
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

    copyMessageList( d, d->flags );
    copyMessageList( d, d->annotations );
    copyMessageList( d, d->addresses );
    copyMessageList( d, d->otherheader );
    copyMessageList( d, d->body );
    copyMessageList( d, d->trivia );
    copyMessageList( d, d->partnumbers );

    log( "Fetching data for " + fn( d->messages.count() ) + " messages. " +
         what.join( " " ) );

    if ( d->messageId ) {
        // we're fetching a message by ID, not UID. just do it.
        makeQueries();
        d->state = Fetching;
        d->messages.clear();
        return;
    }

    MessageSet messages;
    List<Message>::Iterator i( d->messages );
    while ( i ) {
        messages.add( i->uid() );
        ++i;
    }
    uint expected = messages.count();

    // Decide whether to use a transaction or not. We want to use a
    // transaction only if the savings pay for the overhead.
    bool simple = false;
    if ( n == 1 )
        simple = true;
    else if ( messages.isRange() && messages.count() * n < 2000 )
        simple = true;
    else if ( messages.count() * n < 1000 )
        simple = true;

    // Maybe we can turn s into a bigger, but simpler set which
    // returns the same messages.
    if ( !messages.isRange() ) {
        Session * best = 0;
        List<Session>::Iterator it( d->mailbox->sessions() );
        while ( it ) {
            if ( !best || best->nextModSeq() < it->nextModSeq() )
                best = it;
            ++it;
        }
        if ( best )
            messages.addGapsFrom( best->messages() );
    }

    // This selector selects by UID from a single mailbox. We could
    // also use any other Selector, so we can select messages based on
    // anything and retrieve them.
    if ( !d->selector )
        d->selector = new Selector( messages );

    if ( simple ) {
        // a query or two. or three.
        makeQueries();
        d->state = Fetching;
        d->messages.clear();
        return;
    }

    d->batchSize = 1024;
    if ( d->body )
        d->batchSize = d->batchSize / 2;
    if ( d->otherheader )
        d->batchSize = d->batchSize * 2 / 3;
    if ( d->addresses )
        d->batchSize = d->batchSize * 3 / 4;

    // we have to make a transaction. we'll use at least one temporary
    // table to hold the found messages.
    d->t = new Transaction( this );
    String s = "create temporary table matching_messages ("
               "mailbox integer, "
               "uid integer, ";
    if ( d->trivia )
        s.append( "idate integer,"
                  "modseq bigint," );
    s.append( "message integer"
              ") on commit drop" );

    Query * q = new Query( s, 0 );
    d->t->enqueue( q );

    if ( expected > 4 * d->batchSize ) {
        d->tmptable = "using_messages";
        s.replace( "matching_messages", d->tmptable );
        q = new Query( s, 0 );
        d->t->enqueue( q );
    }
    else {
        d->tmptable = "matching_messages";
    }

    StringList wanted;
    wanted.append( "mailbox" );
    wanted.append( "message" );
    wanted.append( "uid" );
    if ( d->trivia ) {
        wanted.append( "idate" );
        wanted.append( "modseq" );
    }
    d->findMessages = d->selector->query( 0, d->mailbox, 0, this,
                                          false, &wanted );
    d->findMessages->setString( "insert into matching_messages "
                                "(" + wanted.join( ", " ) + ") " +
                                d->findMessages->string() );
    d->t->enqueue( d->findMessages );
    d->t->execute();
    d->state = FindingMessages;
    d->messages.clear();
}


/*! Waits for the database to tell us how many messages it inserted
    into the temporary table, and proceeds appropriately.
*/

void Fetcher::findMessages()
{
    if ( !d->findMessages->done() )
        return;

    d->state = Fetching;
    d->messagesExpected = d->findMessages->rows();
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
    if ( d->flags )
        decoders.append( d->flags );
    if ( d->annotations )
        decoders.append( d->annotations );
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

    uint nextUid = 0;
    List<FetcherData::Decoder>::Iterator i( decoders );
    while ( i ) {
        if ( i->q && !i->q->done() )
            return;
        if ( i->uid > nextUid )
            nextUid = i->uid;
        ++i;
    }

    if ( d->tmptable != "using_messages" )
        nextUid = UINT_MAX;

    if ( nextUid ) {
        i = decoders.first();
        while ( i ) {
            i->setDoneUntil( nextUid );
            ++i;
        }
    }

    if ( d->tmptable == "using_messages" ) {
        if ( d->owner )
            d->owner->execute();
        prepareBatch();
        makeQueries();
    }
    else {
        d->state = Done;
        if ( d->owner )
            d->owner->execute();
    }
}


/*! Messages are fetched in batches, so that we can deliver some rows
    early on. This function adjusts the size of the batches so we'll
    get about one batch every 20 seconds, and updates the tables so we
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
            // something in the approximate region of 30 seconds.
            d->batchSize = d->batchSize * 30 / ( now - d->lastBatchStarted );
        }
        log( "Batch time was " + fn ( now - d->lastBatchStarted ) +
             " for " + fn( prevBatchSize ) + " messages, adjusting to " +
             fn( d->batchSize ), Log::Debug );
        if ( d->batchSize < 128 )
            d->batchSize = 128;
        if ( d->batchSize > d->maxBatchSize )
            d->batchSize = d->maxBatchSize;
    }
    d->lastBatchStarted = now;

    // if we would fetch almost all of the messages anyway, skip the
    // bounce table.
    if ( d->messagesExpected <= d->batchSize * 5 / 4 )
        d->tmptable = "matching_messages";

    if ( d->tmptable == "matching_messages" )
        return;

    Query * q = 0;
    if ( d->usingTableFilled ) {
        q = new Query( "delete from using_messages", 0 );
        d->t->enqueue( q );
    }

    String columns = "mailbox, uid, ";
    if ( d->trivia )
        columns.append( "idate, modseq, " );
    columns.append( "message" );
    q = new Query( "insert into using_messages (" + columns + ") "
                   "select " + columns + " from matching_messages "
                   "order by mailbox, uid "
                   "limit " + fn( d->batchSize ),
                   0 );
    d->t->enqueue( q );
    d->usingTableFilled = true;

    q = new Query( "delete from matching_messages "
                   "where (mailbox,uid) in "
                   "(select mailbox,uid from using_messages)", 0 );
    d->t->enqueue( q );
    d->t->execute();

    d->messagesExpected -= d->batchSize;
}


// just a helper to avoid repeated code in makeQueries()
static void appendUsingBit( String & r, Query * & q, FetcherData * d,
                            StringList * wanted, FetcherData::Decoder * owner )
{
    if ( d->tmptable.isEmpty() ) {
        r.append( "(" );
        q = d->selector->query( 0, d->mailbox, 0, owner, false, wanted );
        r.append( q->string() );
        r.append( ")" );
    }
    else {
        q = new Query( "", owner );
        r.append( d->tmptable );
    }
}


/*! Issues the necessary selects to retrieve data and feed the
    decoders. This function is clever about the source (one of the
    temporary tables or the original Selector) and does some
    optimisation of the generated SQL.
*/

void Fetcher::makeQueries()
{
    StringList wanted;
    wanted.append( "mailbox" );
    wanted.append( "uid" );

    List<Query> queries;

    if ( d->flags && !d->messageId ) {
        Query * q = 0;
        String r;
        if ( !d->tmptable.isEmpty() ) {
            // we're using an intermediate table
            r.append( "select f.mailbox, f.uid, f.flag from flags f "
                      "join " );
            r.append( d->tmptable );
            r.append( " m using (mailbox,uid) "
                      "order by f.mailbox, f.uid, f.flag" );
            q = new Query( r, d->flags );
        }
        else if ( d->selector->field() == Selector::Uid ) {
            // we're selecting from a single mailbox based only on UIDs
            r.append( "select mailbox, uid, flag from flags "
                      "where mailbox=$1 and " );
            r.append( d->selector->messageSet().where() );
            r.append( " order by mailbox, uid, flag" );
            q = new Query( r, d->flags );
            q->bind( 1, d->mailbox->id() );
        }
        else {
            // we're selecting complexly. unusual case.
            r.append( "select f.mailbox, f.uid, f.flag from flags f "
                      "join (" );
            q = d->selector->query( 0, d->mailbox, 0, this, false, &wanted );
            r.append( q->string() );
            r.append( ") m using (mailbox,uid) "
                      "order by f.mailbox, f.uid, f.flag" );
            q->setString( r );
        }
        queries.append( q );
        d->flags->q = q;
    }

    wanted.append( "message" );

    if ( d->partnumbers && !d->body && !d->messageId ) {
        // body (below) will handle this as a side effect
        Query * q = 0;
        String r( "select m.uid, p.part, p.bytes, p.lines "
                  "from " );
        appendUsingBit( r, q, d, &wanted, d->partnumbers );
        r.append( " m join part_numbers p using (message) "
                  "order by m.uid, p.part" );
        q->setString( r );
        queries.append( q );
        d->partnumbers->q = q;
    }

    if ( d->annotations && !d->messageId ) {
        Query * q = 0;
        String r( "select a.uid, a.owner, a.value, an.name, an.id "
                  "from annotations a "
                  "join annotation_names an on (a.name=an.id) "
                  "join " );
        appendUsingBit( r, q, d, &wanted, d->annotations );
        r.append( " m using (mailbox,uid)"
                  "order by m.mailbox, m.uid" );
        q->setString( r );
        queries.append( q );
        d->annotations->q = q;
    }

    if ( d->addresses ) {
        Query * q = 0;
        if ( d->messageId ) {
            q = new Query( "select 0 as uid, "
                           "af.part, af.position, af.field, af.number, "
                           "a.name, a.localpart, a.domain "
                           "from address_fields af "
                           "join addresses a on (af.address=a.id) "
                           "where af.message=$1 "
                           "order by af.part, af.field, af.number ",
                           d->addresses );
            q->bind( 1, d->messageId );
        }
        else {
            String r( "select "
                      "m.uid, af.part, af.position, af.field, af.number, "
                      "a.name, a.localpart, a.domain from " );
            appendUsingBit( r, q, d, &wanted, d->addresses );
            r.append( " m join address_fields af using (message) "
                      "join addresses a on (af.address=a.id) "
                      "order by m.uid, af.part, af.field, af.number " );
            q->setString( r );
        }
        queries.append( q );
        d->addresses->q = q;
    }

    if ( d->otherheader ) {
        Query * q = 0;
        if ( d->messageId ) {
            q = new Query( "select 0 as uid, h.part, h.position, "
                           "f.name, h.value from header_fields h "
                           "join field_names f on (h.field=f.id) "
                           "where h.message=$1 "
                           "order by m.uid, h.part",
                           d->otherheader );
            q->bind( 1, d->messageId );
        }
        else {
            String r( "select m.uid, h.part, h.position, "
                      "f.name, h.value from " );
            appendUsingBit( r, q, d, &wanted, d->otherheader );
            r.append( " m join header_fields h using (message) "
                      "join field_names f on (h.field=f.id) "
                      "order by m.uid, h.part" );
            q->setString( r );
        }
        queries.append( q );
        d->otherheader->q = q;
    }

    if ( d->body ) {
        Query * q = 0;
        if ( d->messageId ) {
            Query * q
                = new Query( "select 0 as uid, p.part, b.text, b.data, "
                             "b.bytes as rawbytes, p.bytes, p.lines "
                             "from part_numbers p "
                             "left join bodyparts b on (p.bodypart=b.id) "
                             "where b.id is not null and pn.message=$1"
                             "order by p.part", d->body );
            q->bind( 1, d->messageId );
        }
        else {
            String r( "select m.uid, p.part, b.text, b.data, "
                      "b.bytes as rawbytes, p.bytes, p.lines "
                      "from " );
            appendUsingBit( r, q, d, &wanted, d->body );
            r.append( " m join part_numbers p using (message) "
                      "left join bodyparts b on (p.bodypart=b.id) "
                      "where b.id is not null "
                      "order by m.uid, p.part" );
            q->setString( r );
        }
        queries.append( q );
        d->body->q = q;
    }

    if ( d->trivia && !d->messageId ) {
        Query * q = 0;
        String r;
        if ( !d->tmptable.isEmpty() ) {
            // we're using a transaction, we need to fetch from the table
            q = new Query( r, d->trivia );
            r.append( "select m.id, m2.uid, m2.idate, m.rfc822size, m2.modseq "
                      "from " );
            r.append( d->tmptable );
            r.append( " m2 join messages m on (m2.message=m.id) "
                      "order by m2.uid" );
        }
        else if ( d->selector->field() == Selector::Uid ) {
            // we're selecting messages from a single mailbox, only by UID
            q = new Query( r, d->trivia );
            r.append( "select m.id, mm.uid, mm.idate, m.rfc822size, mm.modseq "
                      "from mailbox_messages mm " );
            r.append( " join messages m on (mm.message=m.id) "
                      "where mailbox=$1 and " );
            r.append( d->selector->messageSet().where( "mm" ) );
            r.append( " order by mm.uid" );
            q->bind( 1, d->mailbox->id() );
        }
        else {
            // we're selecting messages directly, by complex selector
            wanted.append( "idate" );
            wanted.append( "modseq" );
            q = d->selector->query( 0, d->mailbox, 0, this, false, &wanted );
            r.append( "select m.id, m2.uid, mm.idate, m.rfc822size, mm.modseq "
                      "from (" );
            r.append( q->string() );
            r.append( ") m2 join mailbox_messages mm using (mailbox,uid) "
                      "join messages m on (m2.message=m.id) "
                      "order by mm.uid" );
        }
        q->setString( r );
        // because we change wanted in this, we want to make the
        // trivia query last. but we want to execute it as one of the
        // first queries, because it returns so little data. so we call
        // prepend() instead of append().
        queries.prepend( q );
        d->trivia->q = q;
    }

    List<Query>::Iterator q( queries );
    while ( q ) {
        if ( d->t )
            d->t->enqueue( q );
        else
            q->execute();
        ++q;
    }
    if ( !d->t )
        return;

    if ( d->tmptable == "using_messages" )
        d->t->execute();
    else
        d->t->commit();
}


void FetcherData::Decoder::execute()
{
    Message * m = 0;
    uid = 0;
    Row * r = q->nextRow();
    while ( r ) {
        uint u = r->getInt( "uid" );
        if ( u != uid || !m ) {
            uid = u;
            m = 0;
            while ( !messages.isEmpty() &&
                    messages.firstElement()->uid() < uid ) {
                setDone( messages.firstElement() );
                messages.shift();
            }
            if ( !messages.isEmpty() )
                m = messages.firstElement();
        }
        if ( m )
            decode( m, r );
        r = q->nextRow();
    }
    if ( q->done() )
        d->f->execute();
}


void FetcherData::Decoder::setDoneUntil( uint u )
{
    while ( !messages.isEmpty() &&
            messages.firstElement()->uid() <= u ) {
        setDone( messages.firstElement() );
        messages.shift();
    }
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


/*! Instructs this Fetcher to fetch data of type \a t. */

void Fetcher::fetch( Type t )
{
    switch ( t ) {
    case Flags:
        if ( !d->flags )
            d->flags = new FetcherData::FlagsDecoder( d );
        break;
    case Annotations:
        if ( !d->annotations )
            d->annotations = new FetcherData::AnnotationDecoder( d );
        break;
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
    case Flags:
        return d->flags != 0;
        break;
    case Annotations:
        return d->annotations != 0;
        break;
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
