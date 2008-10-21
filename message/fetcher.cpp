// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "fetcher.h"

#include "addressfield.h"
#include "transaction.h"
#include "messageset.h"
#include "annotation.h"
#include "allocator.h"
#include "bodypart.h"
#include "selector.h"
#include "postgres.h"
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
const uint batchHashSize = 1800;


class FetcherData
    : public Garbage
{
public:
    FetcherData()
        : messagesRemaining( 0 ),
          batchIds( 0 ),
          owner( 0 ),
          mailbox( 0 ), session( 0 ),
          q( 0 ),
          findMessages( 0 ),
          transaction( 0 ),
          f( 0 ),
          state( NotStarted ),
          selector( 0 ),
          maxBatchSize( 32768 ),
          batchSize( 0 ),
          uniqueDatabaseIds( true ),
          lastBatchStarted( 0 ),
          flags( 0 ), annotations( 0 ),
          addresses( 0 ), otherheader( 0 ),
          body( 0 ), size( 0 ), trivia( 0 ),
          partnumbers( 0 )
    {}

    List<Message> messages;
    uint messagesRemaining;
    List<Message> * batch[batchHashSize];
    List<uint> * batchIds;
    EventHandler * owner;
    Mailbox * mailbox;
    Session * session;
    List<Query> * q;
    Query * findMessages;
    Transaction * transaction;

    Fetcher * f;
    State state;
    Selector * selector;
    uint maxBatchSize;
    uint batchSize;
    bool uniqueDatabaseIds;
    uint lastBatchStarted;

    class Decoder
        : public EventHandler
    {
    public:
        Decoder( FetcherData * fd )
            : q( 0 ), d( fd ), findById( false ), findByUid( false ) {
            setLog( new Log( Log::Database ) );
        }
        void execute();
        virtual void decode( Message *, Row * ) = 0;
        virtual void setDone( Message * ) = 0;
        virtual bool isDone( Message * ) const = 0;
        Query * q;
        FetcherData * d;

        bool findById;
        bool findByUid;
        List<Message>::Iterator mit;
    };

    Decoder * flags;
    Decoder * annotations;
    Decoder * addresses;
    Decoder * otherheader;
    Decoder * body;
    Decoder * size;
    Decoder * trivia;
    Decoder * partnumbers;

    class FlagsDecoder
        : public Decoder
    {
    public:
        FlagsDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class SizeDecoder
        : public Decoder
    {
    public:
        SizeDecoder( FetcherData * fd )
            : Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class TriviaDecoder
        : public Decoder
    {
    public:
        TriviaDecoder( FetcherData * fd )
            : Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
        bool haveDecided;
        bool findModSeq;
    };

    class AnnotationDecoder
        : public Decoder
    {
    public:
        AnnotationDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class AddressDecoder
        : public Decoder
    {
    public:
        AddressDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class HeaderDecoder
        : public Decoder
    {
    public:
        HeaderDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class PartNumberDecoder
        : public Decoder
    {
    public:
        PartNumberDecoder( FetcherData * fd ): Decoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
    };

    class BodyDecoder
        : public PartNumberDecoder
    {
    public:
        BodyDecoder( FetcherData * fd ): PartNumberDecoder( fd ) {}
        void decode( Message *, Row * );
        void setDone( Message * );
        bool isDone( Message * ) const;
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


/*! Constructs a Fetcher which will fetch the single message \a m by
    Message::databaseId() and notify \a owner when it's done.

    The constructed Fetcher can only fetch bodies, headers and
    addresses.
*/

Fetcher::Fetcher( Message * m, EventHandler * owner )
    : EventHandler(), d( new FetcherData )
{
    setLog( new Log( Log::Database ) );
    d->mailbox = 0;
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
    if ( d->size ) {
        n++;
        what.append( "size" );
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

    if ( d->messages.count() == 1 && !d->trivia &&
         d->messages.firstElement()->databaseId() ) {
        // we're fetching a message by ID, not UID. just do it.
        d->batchSize = 1;
        d->messagesRemaining = 1;
        prepareBatch();
        makeQueries();
        d->state = Fetching;
        return;
    }

    MessageSet messages;
    List<Message>::Iterator i( d->messages );
    while ( i ) {
        messages.add( i->uid( d->mailbox ) );
        ++i;
    }
    uint expected = messages.count();

    // Decide whether to use a separate query for finding the
    // messages. We want to use the extra query only if the savings
    // pay for the overhead.
    bool simple = false;
    if ( n == 1 )
        simple = true;
    else if ( messages.isRange() && expected * n < 2000 )
        simple = true;
    else if ( expected * n < 1000 )
        simple = true;

    // This selector selects by UID from a single mailbox. We could
    // also use any other Selector, so we can select messages based on
    // anything and retrieve them.
    if ( !d->selector )
        d->selector = new Selector( messages );

    if ( ( d->flags || d->annotations ) && !d->transaction && n > 1 )
        d->transaction = new Transaction( this );
    if ( d->transaction && n > 1 )
        simple = false;

    if ( simple ) {
        // a query or two. or at most three.
        makeQueries();
        d->state = Fetching;
        return;
    }

    // we'll use two steps. first, we find a good size for the first
    // batch.
    d->batchSize = 1024;
    if ( d->body )
        d->batchSize = d->batchSize / 2;
    if ( d->otherheader )
        d->batchSize = d->batchSize * 2 / 3;
    if ( d->addresses )
        d->batchSize = d->batchSize * 3 / 4;

    StringList wanted;
    wanted.append( "message" );
    wanted.append( "uid" );
    if ( d->trivia ) {
        wanted.append( "idate" );
        wanted.append( "modseq" );
    }
    d->findMessages = d->selector->query( 0, d->mailbox, d->session, this,
                                          true, &wanted );
    if ( d->flags || d->annotations )
        d->findMessages->setString( d->findMessages->string() +
                                    " for update" );
    submit( d->findMessages );
    d->state = FindingMessages;
    if ( d->transaction )
        d->transaction->execute();
}


/*! Waits for the database to tell us how many messages it inserted
    into the temporary table, and proceeds appropriately.
*/

void Fetcher::findMessages()
{
    if ( !d->findMessages->done() )
        return;

    Row * r = d->findMessages->nextRow();
    if ( r ) {
        bool modseq = false;
        if ( r->hasColumn( "modseq" ) )
            modseq = true;
        List<Message>::Iterator m( d->messages );
        while ( r ) {
            d->messagesRemaining++;
            uint uid = r->getInt( "uid" );
            while ( m && m->uid( d->mailbox ) < uid )
                ++m;
            if ( m ) {
                m->setDatabaseId( r->getInt( "message" ) );
                if ( modseq ) {
                    m->setModSeq( d->mailbox, r->getBigint( "modseq" ) );
                    m->setInternalDate( d->mailbox, r->getInt( "idate" ) );
                }
            }
            r = d->findMessages->nextRow();
        }
    }

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
    if ( d->size )
        decoders.append( d->size );
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

    if ( d->batchSize ) {
        i = decoders.first();
        while ( i ) {
            uint n = 0;
            while ( n < batchHashSize ) {
                if ( d->batch[n] ) {
                    List<Message>::Iterator m( d->batch[n] );
                    while ( m ) {
                        i->setDone( m );
                        ++m;
                    }
                }
                n++;
            }
            ++i;
        }
    }
    else {
        while ( !d->messages.isEmpty() ) {
            i = decoders.first();
            Message * m = d->messages.firstElement();
            while ( i ) {
                i->setDone( m );
                ++i;
            }
            d->messages.shift();
        }
    }

    if ( d->messages.isEmpty() ) {
        d->state = Done;
        if ( d->transaction )
            d->transaction->commit();
        if ( d->owner )
            d->owner->notify();
    }
    else {
        prepareBatch();
        makeQueries();
    }
}


/*! Messages are fetched in batches, so that we can deliver some rows
    early on. This function adjusts the size of the batches so we'll
    get about one batch every 90 seconds, and updates the tables so we
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
            // something in the approximate region of 90 seconds.
            uint diff = now - d->lastBatchStarted;
            d->batchSize = d->batchSize * 90 / diff;
        }
        if ( d->batchSize > prevBatchSize * 3 )
            d->batchSize = prevBatchSize * 3;
        if ( d->batchSize > prevBatchSize + 2000 )
            d->batchSize = prevBatchSize + 2000;
        if ( d->batchSize < 128 )
            d->batchSize = 128;
        if ( d->batchSize > d->maxBatchSize )
            d->batchSize = d->maxBatchSize;
        log( "Batch time was " + fn ( now - d->lastBatchStarted ) +
             " for " + fn( prevBatchSize ) + " messages, adjusting to " +
             fn( d->batchSize ), Log::Debug );
    }
    d->lastBatchStarted = now;

    // if we would fetch almost all of the messages, increase the
    // batch size to avoid a very small last batch.
    if ( d->messagesRemaining <= d->batchSize * 5 / 4 )
        d->batchSize = d->messagesRemaining;

    // Find out which messages we're going to fetch, and fill in the
    // batch array so we can tie responses to the Message objects.
    // More than one Message may refer to the same row. This code
    // carefully counts expected rows rather than affected Message
    // objects. Shouldn't matter much, except that it makes the batch
    // time calculator above happier.
    d->uniqueDatabaseIds = true;
    uint n = 0;
    while ( n < batchHashSize )
        d->batch[n++] = 0;
    d->batchIds = new List<uint>;
    n = 0;
    while ( !d->messages.isEmpty() && n < d->batchSize ) {
        Message * m = d->messages.firstElement();
        d->messages.shift();
        uint id = m->databaseId();
        uint b = id % batchHashSize;
        if ( d->batch[b] ) {
            List<Message>::Iterator o( d->batch[b] );
            while ( o && o->databaseId() != id )
                ++o;
            if ( o ) {
                d->uniqueDatabaseIds = false;
            }
            else {
                n++;
                d->batchIds->append( new uint( id ) );
            }
        }
        else {
            d->batch[b] = new List<Message>;
            d->batchIds->append( new uint( m->databaseId() ) );
            n++;
        }
        d->batch[b]->append( m );
        d->messagesRemaining--;
    }
}


/*! Makes and returns a MessageSet containing all the UIDs to be used
    for the coming batch.

    This function silently assumes that all the messages are in the
    same Mailbox.
*/

MessageSet * Fetcher::findUids()
{
    MessageSet * s = new MessageSet;
    uint n = 0;
    while ( n < batchHashSize ) {
        if ( d->batch[n] ) {
            List<Message>::Iterator m( d->batch[n] );
            while ( m ) {
                s->add( m->uid( d->mailbox ) );
                ++m;
            }
        }
        n++;
    }
    return s;
}


static void bindUids( Query * q, uint n, MessageSet * s1, Selector * s2 )
{
    bool one = false;
    if ( s1 && s1->count() == 1 )
        one = true;
    else if ( !s1 && s2->messageSet().count() == 1 )
        one = true;
    if ( one ) {
        String s = q->string();
        s.replace( "=any($" + fn( n ) + ")", "=$" + fn( n ) );
        q->setString( s );
        if ( s1 )
            q->bind( n, s1->smallest() );
        else
            q->bind( n, s2->messageSet().smallest() );
    }
    else {
        if ( s1 )
            q->bind( n, *s1 );
        else
            q->bind( n, s2->messageSet() );
    }
}


static void bindBatchIds( Query * q, uint n, List<uint> * l )
{
    if ( l->firstElement() &&
         l->firstElement() == l->lastElement() ) {
        String s = q->string();
        s.replace( "=any($" + fn( n ) + ")", "=$" + fn( n ) );
        q->setString( s );
        q->bind( n, *l->firstElement() );
    }
    else {
        q->bind( n, l );
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

    MessageSet * uids = 0;

    Query * q = 0;
    String r;

    if ( d->flags && d->mailbox ) {
        if ( d->batchSize ) {
            r = "select mm.message, mm.mailbox, mm.uid, f.flag "
                "from mailbox_messages mm "
                "join flags f using (mailbox,uid) "
                "where mm.mailbox=$1 and mm.message=any($2) "
                "order by mm.mailbox, mm.uid, f.flag";
            q = new Query( r, d->flags );
            q->bind( 1, d->mailbox->id() );
            bindBatchIds( q, 2, d->batchIds );
        }
        else if ( d->selector->field() == Selector::Uid ) {
            r = "select mailbox, uid, flag from flags "
                "where mailbox=$1 and uid=any($2) "
                "order by mailbox, uid, flag";
            q = new Query( r, d->flags );
            q->bind( 1, d->mailbox->id() );
            bindUids( q, 2, uids, d->selector );
        }
        else {
            // we're selecting complexly and not using
            // batches. perhaps due to IMAP 'fetch 1:* (uid flags)
            // (changedsince 1232)' in a smallish mailbox.
            q = d->selector->query( 0, d->mailbox, d->session, d->flags,
                                    false, &wanted );
            r = q->string();
            r.replace( " where ",
                       " left join flags f on"
                       " (mm.mailbox=f.mailbox and m.uid=f.uid)"
                       " where " );
            r.replace( "select mm.",
                       "select f.flag, mm." );
            r.append( " order by mm.mailbox, mm.uid, f.flag" );
            q->setString( r );
        }
        submit( q );
        d->flags->q = q;
    }

    if ( d->annotations && d->mailbox ) {
        if ( d->batchSize ) {
            q = new Query( "select mm.message, a.mailbox, a.uid, "
                           "a.owner, a.value, an.name, an.id "
                           "from mailbox_messages mm "
                           "join annotations a using (mailbox,uid) "
                           "join annotation_names an on (a.name=an.id) "
                           "where mm.mailbox=$1 and mm.message=any($2) "
                           "order by a.mailbox, a.uid",
                           d->annotations );
            q->bind( 1, d->mailbox->id() );
            bindBatchIds( q, 2, d->batchIds );
        }
        else if ( d->selector->field() == Selector::Uid ) {
            q = new Query( "select a.mailbox, a.uid, "
                           "a.owner, a.value, an.name, an.id "
                           "from annotations a "
                           "join annotation_names an on (a.name=an.id) "
                           "where a.mailbox=$1 and a.uid=any($2) "
                           "order by a.mailbox, a.uid",
                           d->annotations );
            q->bind( 1, d->mailbox->id() );
            bindUids( q, 2, uids, d->selector );
        }
        else {
            // we're selecting complexly and not using batches. perhaps
            // due to IMAP 'fetch 1:* (uid annotations) (changedsince 1232)'
            q = d->selector->query( 0, d->mailbox, d->session,
                                    d->annotations, false, &wanted );
            r = q->string();
            if ( !r.contains( " join annotations " ) )
                r.replace( " where ",
                           " join annotations a on"
                           " (mm.mailbox=a.mailbox and mm.uid=a.uid)"
                           " where " );
            r.replace( " where ",
                       " join annotation_names an on (a.name=an.id)"
                       " where " );
            r.replace( "select mm.",
                       "select a.mailbox, a.uid, "
                       "a.owner, a.value, an.name, an.id, mm." );
            r.append( " order by f.mailbox, f.uid, f.flag" );
            q->setString( r );
        }
        submit( q );
        d->annotations->q = q;
    }

    wanted.append( "message" );

    if ( d->partnumbers && !d->body ) {
        // body (below) will handle this as a side effect
        if ( !d->batchSize ) {
            q = d->selector->query( 0, d->mailbox, d->session, d->partnumbers,
                                    false, &wanted );
            r = q->string();
            if ( !r.contains( " join part_numbers pn " ) )
                r.replace( " where ",
                           " join part_numbers pn on"
                           " (mm.message=pn.message)"
                           " where " );
            r.replace( "select mm.",
                       "select pn.part, pn.bytes, pn.lines, mm." );
            r.append( " order by mm.uid, pn.part" );
            q->setString( r );
        }
        else {
            q = new Query( "select message, part, bytes, lines "
                           "from part_numbers where message=any($1)",
                           d->partnumbers );
            q->bind( 1, d->batchIds );
        }
        submit( q );
        d->partnumbers->q = q;
    }

    if ( d->addresses ) {
        if ( !d->batchSize ) {
            q = d->selector->query( 0, d->mailbox, d->session, d->addresses,
                                    false, &wanted );
            r = q->string();
            r.replace( "select mm.",
                       "select "
                       "af.part, af.position, af.field, af.number, "
                       "a.name, a.localpart, a.domain, mm." );
            r.replace( " where ",
                       " join address_fields af on (mm.message=af.message)"
                       " join addresses a on (af.address=a.id) where " );
            r.append( " order by mm.uid, af.part, af.field, af.number" );
            q->setString( r );
        }
        else {
            q = new Query( "select af.message, "
                           "af.part, af.position, af.field, af.number, "
                           "a.name, a.localpart, a.domain "
                           "from address_fields af "
                           "join addresses a on (af.address=a.id) "
                           "where af.message=any($1) "
                           "order by af.message, af.part, af.field, af.number",
                           d->addresses );
            bindBatchIds( q, 1, d->batchIds );
        }
        submit( q );
        d->addresses->q = q;
    }

    if ( d->otherheader ) {
        if ( !d->batchSize ) {
            q = d->selector->query( 0, d->mailbox, d->session, d->otherheader,
                                    false, &wanted );
            r = q->string();
            r.replace( "select mm.",
                       "select "
                       "hf.part, hf.position, fn.name, hf.value, mm." );
            r.replace( " where ",
                       " join header_fields hf on (mm.message=hf.message)"
                       " join field_names fn on (hf.field=fn.id) where " );
            r.append( " order by mm.uid, hf.part" );
            q->setString( r );
        }
        else {
            q = new Query( "select hf.message, hf.part, hf.position, "
                           "fn.name, hf.value from header_fields hf "
                           "join field_names fn on (hf.field=fn.id) "
                           "where hf.message=any($1) "
                           "order by hf.message, hf.part",
                           d->otherheader );
            bindBatchIds( q, 1, d->batchIds );
        }
        submit( q );
        d->otherheader->q = q;
    }

    if ( d->body ) {
        if ( !d->batchSize ) {
            q = d->selector->query( 0, d->mailbox, d->session, d->body,
                                    false, &wanted );
            r = q->string();
            if ( !r.contains( " join bodyparts bp " ) )
                r.replace( " where ",
                           " join part_numbers pn on"
                           " (mm.message=pn.message)"
                           " left join bodyparts bp on"
                           " (pn.bodypart=bp.id)"
                           " where " );
            r.replace( "select mm.",
                       "select "
                       "pn.part, bp.text, bp.data, "
                       "bp.bytes as rawbytes, pn.bytes, pn.lines, mm." );
            r.append( " order by mm.uid, pn.part" );
            q->setString( r );
        }
        else {
            q = new Query( "select pn.message, pn.part, bp.text, bp.data, "
                           "bp.bytes as rawbytes, pn.bytes, pn.lines "
                           "from part_numbers pn "
                           "left join bodyparts bp on (pn.bodypart=bp.id) "
                           "where pn.message=any($1)",
                           d->body );
            bindBatchIds( q, 1, d->batchIds );
        }
        submit( q );
        d->body->q = q;
    }

    if ( d->size ) {
        if ( !d->batchSize ) {
            q = d->selector->query( 0, d->mailbox, d->session, d->size,
                                    true, &wanted );
            r = q->string();
            if ( !r.contains( " join messages " ) )
                r.replace( " where ",
                           " join messages m on (mm.message=m.id)"
                           " where " );
            r.replace( "select mm.",
                       "select m.rfc822size, mm." );
            q->setString( r );
        }
        else {
            q = new Query( "select id as message, rfc822size "
                           "from messages where id=any($1)", d->size );
            bindBatchIds( q, 1, d->batchIds );
        }
        submit( q );
        d->size->q = q;
    }

    if ( d->trivia ) {
        if ( !d->batchSize ) {
            wanted.append( "idate" );
            wanted.append( "modseq" );
            q = d->selector->query( 0, d->mailbox, d->session, d->trivia,
                                    true, &wanted );
            submit( q );
            d->trivia->q = q;
        }
        else {
            // we have to have handled that already
        }
    }
    if ( d->transaction )
        d->transaction->execute();
}


void FetcherData::Decoder::execute()
{
    Scope x( log() );
    Row * r = q->nextRow();
    if ( r && !findByUid && !findById ) {
        if ( r->hasColumn( "message" ) ) {
            findById = true;
        }
        else if ( r->hasColumn( "uid" ) ) {
            mit = d->messages.first();
            findByUid = true;
        }
    }

    if ( !r ) {
        // no rows, no work
    }
    else if ( findByUid ) {
        while ( r ) {
            uint uid = r->getInt( "uid" );
            while ( mit && mit->uid( d->mailbox ) < uid )
                ++mit;
            if ( mit && !isDone( mit ) )
                decode( mit, r );
            r = q->nextRow();
        }
    }
    else if ( findById ) {
        while ( r ) {
            uint id = r->getInt( "message" );
            uint b = id%batchHashSize;
            bool more = true;
            if ( d->batch[b] ) {
                List<Message>::Iterator m( d->batch[b] );
                while ( m && more ) {
                    if ( m->databaseId() == id ) {
                        if ( !isDone( m ) )
                            decode( m, r );
                        if ( d->uniqueDatabaseIds )
                            more = false;
                    }
                    ++m;
                }
            }
            r = q->nextRow();
        }
    }
    if ( q->done() )
        d->f->execute();
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


void FetcherData::HeaderDecoder::setDone( Message * m )
{
    m->setHeadersFetched();
}


bool FetcherData::HeaderDecoder::isDone( Message * m ) const
{
    return m->hasHeaders();
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


bool FetcherData::AddressDecoder::isDone( Message * m ) const
{
    return m->hasAddresses();
}


void FetcherData::FlagsDecoder::decode( Message * m, Row * r )
{
    String f = Flag::name( r->getInt( "flag" ) );
    if ( !f.isEmpty() ) {
        m->setFlag( d->mailbox, f );
    }
    else {
        // XXX: consider this. The best course of action may be to
        // silently ignore this flag for now. it's new, so we didn't
        // announce it in the select response, either.
    }
}


void FetcherData::FlagsDecoder::setDone( Message * m )
{
    m->setFlagsFetched( d->mailbox, true );

}


bool FetcherData::FlagsDecoder::isDone( Message * m ) const
{
    return m->hasFlags( d->mailbox );
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


bool FetcherData::PartNumberDecoder::isDone( Message * m ) const
{
    return m->hasBytesAndLines();
}


void FetcherData::SizeDecoder::decode( Message * m , Row * r )
{
    m->setRfc822Size( r->getInt( "rfc822size" ) );
}


void FetcherData::SizeDecoder::setDone( Message * m )
{
    m->setSizeFetched();
}


bool FetcherData::SizeDecoder::isDone( Message * m ) const
{
    return m->hasSize();
}


void FetcherData::TriviaDecoder::decode( Message * m , Row * r )
{
    m->setInternalDate( d->mailbox, r->getInt( "idate" ) );
    m->setModSeq( d->mailbox, r->getBigint( "modseq" ) );
}


void FetcherData::TriviaDecoder::setDone( Message * m )
{
    m->setTriviaFetched( d->mailbox, true );
}


bool FetcherData::TriviaDecoder::isDone( Message * m ) const
{
    return m->hasTrivia( d->mailbox );
}


void FetcherData::AnnotationDecoder::decode( Message * m, Row * r )
{
    uint id = r->getInt( "id" );

    String n( AnnotationName::name( id ) );
    if ( n.isEmpty() ) {
        n = r->getString( "name" );
        AnnotationName::add( n, id );
    }

    String v( r->getString( "value" ) );

    uint owner = 0;
    if ( !r->isNull( "owner" ) )
        owner = r->getInt( "owner" );

    Annotation * a = new Annotation( n, v, owner );
    m->replaceAnnotation( d->mailbox, a );
}


void FetcherData::AnnotationDecoder::setDone( Message * m )
{
    m->setAnnotationsFetched( d->mailbox, true );
}


bool FetcherData::AnnotationDecoder::isDone( Message * m ) const
{
    return m->hasAnnotations( d->mailbox );
}


/*! Instructs this Fetcher to fetch data of type \a t. */

void Fetcher::fetch( Type t )
{
    Scope x( log() );
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
    case Size:
        if ( !d->size )
            d->size = new FetcherData::SizeDecoder( d );
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
    case Size:
        return d->size != 0;
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


/*! Tells the Fetcher that its return values will be used in \a
    s. Knowing the target Session enables the Fetcher to optimise some
    queries.
*/

void Fetcher::setSession( class Session * s )
{
    d->session = s;
}


/*! Records that all queries done by this Fetcher should be performed
    within \a t. This can be useful e.g. if some messages may be
    locked by \a t, or if the retrieval is tied to \a t logically.
 */

void Fetcher::setTransaction( class Transaction * t )
{
    d->transaction = t->subTransaction();
}


/*! This internal helper makes sure \a q is executed by the
    database.
*/

void Fetcher::submit( Query * q )
{
    if ( d->transaction )
        d->transaction->enqueue( q );
    else
        q->execute();
}
