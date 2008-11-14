// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "injector.h"

#include "map.h"
#include "dict.h"
#include "flag.h"
#include "query.h"
#include "address.h"
#include "message.h"
#include "ustring.h"
#include "mailbox.h"
#include "bodypart.h"
#include "datefield.h"
#include "fieldname.h"
#include "mimefields.h"
#include "messagecache.h"
#include "helperrowcreator.h"
#include "addressfield.h"
#include "transaction.h"
#include "annotation.h"
#include "session.h"
#include "scope.h"
#include "graph.h"
#include "html.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "dsn.h"


static PreparedStatement *lockUidnext;
static PreparedStatement *incrUidnext;
static PreparedStatement *incrUidnextWithRecent;

static GraphableCounter * successes;
static GraphableCounter * failures;


struct BodypartRow
    : public Garbage
{
    BodypartRow()
        : id( 0 ), text( 0 ), data( 0 ), bytes( 0 )
    {}

    uint id;
    String hash;
    String * text;
    String * data;
    uint bytes;
    List<Bodypart> bodyparts;
};


static String addressKey( Address * a )
{
    String r;
    r.append( a->uname().utf8() );
    r.append( '\0' );
    r.append( a->localpart() );
    r.append( '\0' );
    r.append( a->domain().lower() );
    return r;
}

class AddressCreator
    : public EventHandler
{
public:
    Dict<Address> * addresses;
    Transaction * parent;
    Transaction * t;
    Query * q;
    uint state;
    Dict<Address> unided;

    AddressCreator( Dict<Address> * a, Transaction * tr )
        : addresses( a ), parent( tr ), t( 0 ), q( 0 ), state( 0 )
    {
    }

    void execute();
    void selectAddresses();
    void processAddresses();
    void insertAddresses();
    void processInsert();

    bool done() { return state > 3; }
};

void AddressCreator::execute()
{
    uint s = 4;
    while ( s != state ) {
        s = state;

        if ( state == 0 )
            selectAddresses();
        if ( state == 1 )
            processAddresses();
        if ( state == 2 )
            insertAddresses();
        if ( state == 3 )
            processInsert();
    };
}

void AddressCreator::selectAddresses()
{
    q = new Query( "", this );

    String s( "select id, name, localpart, domain "
              "from addresses where " );

    unided.clear();

    uint i = 0;
    StringList sl;
    Dict<Address>::Iterator it( addresses );
    while ( it && i < 128 ) {
        Address * a = it;
        if ( !a->id() ) {
            int n = 3*i+1;
            String p;
            unided.insert( addressKey( a ), a );
            q->bind( n, a->uname() );
            p.append( "(name=$" );
            p.append( fn( n++ ) );
            q->bind( n, a->localpart() );
            p.append( " and localpart=$" );
            p.append( fn( n++ ) );
            q->bind( n, a->domain().lower() );
            p.append( " and lower(domain)=$" );
            p.append( fn( n++ ) );
            p.append( ")" );
            sl.append( p );
            ++i;
        }
        ++it;
    }
    s.append( sl.join( " or " ) );
    q->setString( s );
    q->allowSlowness();

    if ( i == 0 ) {
        state = 4;
        if ( t )
            t->commit();
        else
            parent->notify();
    }
    else {
        state = 1;
        if ( t ) {
            t->enqueue( q );
            t->execute();
        }
        else {
            parent->enqueue( q );
            parent->execute();
        }
    }
}

void AddressCreator::processAddresses()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        Address * a =
            new Address( r->getUString( "name" ),
                         r->getString( "localpart" ),
                         r->getString( "domain" ) );

        Address * orig =
            unided.remove( addressKey( a ) );
        if ( orig )
            orig->setId( r->getInt( "id" ) );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() )
        state = 0;
    else
        state = 2;
}

void AddressCreator::insertAddresses()
{
    if ( !t )
        t = parent->subTransaction( this );
    q = new Query( "copy addresses (name,localpart,domain) "
                   "from stdin with binary", this );
    Dict<Address>::Iterator it( unided );
    while ( it ) {
        Address * a = it;
        q->bind( 1, a->uname() );
        q->bind( 2, a->localpart() );
        q->bind( 3, a->domain() );
        q->submitLine();
        ++it;
    }

    state = 3;
    t->enqueue( q );
    t->execute();
}

void AddressCreator::processInsert()
{
    if ( !q->done() )
        return;

    if ( !q->failed() ) {
        state = 0;
    }
    else if ( q->error().contains( "addresses_nld_key" ) ) {
        t->restart();
        state = 0;
    }
    else {
        state = 4;
        t->commit();
    }
}


// The following is everything the Injector needs to do its work.

enum State {
    Inactive,
    CreatingDependencies,
    InsertingBodyparts,
    SelectingMessageIds, SelectingUids,
    InsertingMessages,
    AwaitingCompletion, Done
};


class InjectorData
    : public Garbage
{
public:
    InjectorData()
        : owner( 0 ),
          state( Inactive ), failed( false ), transaction( 0 ),
          fieldNameCreator( 0 ), flagCreator( 0 ), annotationNameCreator( 0 ),
          queries( 0 ), select( 0 ), insert( 0 ), copy( 0 ), message( 0 ),
          substate( 0 ), subtransaction( 0 )
    {}

    struct Delivery
        : public Garbage
    {
        Delivery( Injectee * m, Address * a, List<Address> * l )
            : message( m ), sender( a ), recipients( l )
        {}

        Injectee * message;
        Address * sender;
        List<Address> * recipients;
    };

    List<Message> messages;
    List<Injectee> injectables;
    List<Delivery> deliveries;

    EventHandler * owner;

    State state;
    bool failed;

    Transaction *transaction;

    StringList flags;
    StringList fields;
    StringList annotationNames;
    Dict<Address> addresses;

    struct Mailbox
        : public Garbage
    {
        Mailbox( ::Mailbox * m ): Garbage(), mailbox( m ) {}
        ::Mailbox * mailbox;
        List<Injectee> messages;
    };

    Map<Mailbox> mailboxes;

    HelperRowCreator * fieldNameCreator;
    HelperRowCreator * flagCreator;
    HelperRowCreator * annotationNameCreator;

    List<Query> * queries;
    Query * select;
    Query * insert;
    Query * copy;
    List<Message>::Iterator * message;

    uint substate;
    Transaction * subtransaction;

    Dict<BodypartRow> hashes;
    List<BodypartRow> bodyparts;
};


/*! \class Injector injector.h
    Stores message objects in the database.

    This class takes a list of Message objects and performs the database
    operations necessary to inject them into their respective mailboxes.
    Injection commences only when execute() is called.
*/


/*! This setup function expects to be called by ::main() to perform what
    little initialisation is required by the Injector.
*/

void Injector::setup()
{
    lockUidnext =
        new PreparedStatement(
            "select id,uidnext,nextmodseq,first_recent from mailboxes "
            "where id=$1 for update"
        );

    incrUidnext =
        new PreparedStatement(
            "update mailboxes "
            "set uidnext=uidnext+$2,nextmodseq=nextmodseq+1 "
            "where id=$1"
        );

    incrUidnextWithRecent =
        new PreparedStatement(
            "update mailboxes "
            "set uidnext=uidnext+$2,"
                 "nextmodseq=nextmodseq+1,"
                 "first_recent=first_recent+$2 "
            "where id=$1"
        );

    ::failures = new GraphableCounter( "injection-errors" );
    ::successes = new GraphableCounter( "messages-injected" );
}


/*! Creates a new Injector to inject messages into the database on
    behalf of the \a owner, which is notified when the injection is
    completed.
*/

Injector::Injector( EventHandler * owner )
    : d( new InjectorData )
{
    if ( !lockUidnext )
        setup();

    d->owner = owner;
}


/*!  Notes that \a messages must be injected into the database. */

void Injector::addInjection( List<Injectee> * messages )
{
    if ( !messages || messages->isEmpty() )
        return;

    List<Injectee>::Iterator i( messages );
    while ( i ) {
        d->injectables.append( i );
        ++i;
    }
}


/*! Notes that \a message must be injected, and spooled for delivery
    to the specified \a recipients from the given \a sender.
*/

void Injector::addDelivery( Injectee * message, Address * sender,
                            List<Address> * recipients )
{
    d->deliveries.append( new InjectorData::Delivery( message, sender,
                                                      recipients ) );
}


/*! Returns true if this injector has finished its work, and false if it
    hasn't started or is currently working.
*/

bool Injector::done() const
{
    return ( d->failed || d->state == Done );
}


/*! Returns true if this injection failed, and false if it has succeeded
    or is in progress.
*/

bool Injector::failed() const
{
    return d->failed;
}


/*! Returns an error message if injection failed, or an empty string
    if it succeeded or hasn't failed yet.
*/

String Injector::error() const
{
    if ( !d->failed )
        return "";

    List<Message>::Iterator it( d->messages );
    while ( it ) {
        Message * m = it;
        if ( !m->valid() )
            return m->error();
        ++it;
    }

    if ( !d->transaction )
        return "";
    return d->transaction->error();
}


/*! This private function advances the injector to the next state. */

void Injector::next()
{
    d->state = (State)(d->state + 1);
}


void Injector::execute()
{
    Scope x( log() );

    State last;

    // We start in state Inactive, and execute the functions responsible
    // for making progress in each state. If they change the state using
    // next(), we restart the loop; otherwise we wait for callbacks. We
    // check for errors after each call, so the functions don't need to
    // do anything about errors, other than returning early or setting
    // d->failed (if the error doesn't affect the Transaction).

    do {
        last = d->state;
        switch ( d->state ) {
        case Inactive:
            findMessages();
            findDependencies();
            if ( d->failed )
                break;
            logDescription();
            if ( d->messages.isEmpty() ) {
                d->state = Done;
            }
            else {
                d->transaction = new Transaction( this );
                next();
            }
            break;

        case CreatingDependencies:
            createDependencies();
            break;

        case InsertingBodyparts:
            insertBodyparts();
            break;

        case SelectingMessageIds:
            selectMessageIds();
            break;

        case SelectingUids:
            selectUids();
            break;

        case InsertingMessages:
            insertMessages();
            insertDeliveries();
            next();
            if ( !d->mailboxes.isEmpty() ) {
                cache();
                Mailbox::refreshMailboxes( d->transaction );
            }
            d->transaction->commit();
            break;

        case AwaitingCompletion:
            if ( !d->transaction->done() )
                return;

            if ( d->failed || d->transaction->failed() ) {
                ::failures->tick();
                Cache::clearAllCaches();
            }
            else {
                ::successes->tick();
            }

            next();
            break;

        case Done:
            break;
        }

        if ( !d->failed && d->transaction )
            d->failed = d->transaction->failed();

        if ( d->state < AwaitingCompletion && d->failed ) {
            if ( d->transaction ) {
                d->state = AwaitingCompletion;
                d->transaction->rollback();
            }
            else {
                break;
            }
        }
    }
    while ( last != d->state && d->state != Done );

    if ( d->state == Done && d->owner ) {
        if ( d->failed )
            log( "Injection failed: " + error() );
        else
            log( "Injection succeeded" );

        // We don't want to notify the owner multiple times if we
        // aborted early and continue to get callbacks for failed
        // queries.

        EventHandler * owner = d->owner;
        d->owner = 0;
        owner->execute();
    }
}


/*! This private helper makes a master list of messages to be
    inserted, based on what addDelivery() and addInjection() have
    done.
*/

void Injector::findMessages()
{
    PatriciaTree<Injectee> unique;
    List<Injectee>::Iterator im( d->injectables );
    while ( im ) {
        Injectee * m = im;
        if ( !unique.find( (const char *)&m, sizeof(m) * 8 ) ) {
            unique.insert( (const char *)&m, sizeof(m) * 8, m );
            d->messages.append( m );
        }
        ++im;
    }
    List<InjectorData::Delivery>::Iterator dm( d->deliveries );
    while ( dm ) {
        Injectee * m = dm->message;
        if ( !unique.find( (const char *)&m, sizeof(m) * 8 ) ) {
            unique.insert( (const char *)&m, sizeof(m) * 8, m );
            d->messages.append( m );
        }
        ++dm;
    }
    log( "Injecting " + fn( d->messages.count() ) + " messages (" +
         fn( d->injectables.count() ) + ", " +
         fn( d->deliveries.count() ) + ")", Log::Debug );
}


/*! This private function looks through the list of messages given to
    this Injector, to make sure that they are all valid, and to collect
    lists of any unknown header field names, flags, annotation names, or
    addresses.

    In the common case there will be few, if any, entries to insert into
    the *_names tables, so we build lists of them without worrying about
    memory use. The list of addresses may be large, but we can't avoid
    building that list anyway.
*/

void Injector::findDependencies()
{
    Dict<Injector> seenFields;

    List<Header> * l = new List<Header>;

    List<Message>::Iterator it( d->messages );
    while ( it ) {
        Message * m = it;
        ++it;

        if ( !m->valid() ) {
            d->failed = true;
            return;
        }

        // Collect the headers for this message.

        l->clear();
        l->append( m->header() );
        List<Bodypart>::Iterator bi( m->allBodyparts() );
        while ( bi ) {
            Bodypart *bp = bi;
            l->append( bp->header() );
            if ( bp->message() )
                l->append( bp->message()->header() );
            ++bi;
        }

        // And then step through them, looking for unknown fields and
        // address fields.

        List<Header>::Iterator hi( l );
        while ( hi ) {
            Header * hdr = hi;
            List< HeaderField >::Iterator fi( hdr->fields() );
            while ( fi ) {
                HeaderField *hf = fi;
                String n( hf->name() );

                if ( hf->type() >= HeaderField::Other &&
                     FieldName::id( n ) == 0 && !seenFields.contains( n ) )
                {
                    d->fields.append( n );
                    seenFields.insert( n, this );
                }

                if ( hf->type() <= HeaderField::LastAddressField )
                    updateAddresses( ((AddressField *)hf)->addresses() );

                ++fi;
            }
            ++hi;
        }
    }

    Dict<String> flags;
    Dict<String> annotationNames;

    List<Injectee>::Iterator imi( d->injectables );
    while ( imi ) {
        Injectee * m = imi;
        ++imi;

        // Then look through this message's mailboxes to find any
        // unknown flags or annotation names; and to build a list
        // of unique mailboxes for use later.

        List<Mailbox>::Iterator mi( m->mailboxes() );
        while ( mi ) {
            Mailbox * mb = mi;
            InjectorData::Mailbox * mbc = d->mailboxes.find( mb->id() );
            if ( !mbc ) {
                mbc = new InjectorData::Mailbox( mb );
                d->mailboxes.insert( mb->id(), mbc );
            }
            mbc->messages.append( m );

            StringList::Iterator fi( m->flags( mb ) );
            while ( fi ) {
                flags.insert( *fi, fi );
                ++fi;
            }

            List<Annotation>::Iterator ai( m->annotations( mb ) );
            while ( ai ) {
                Annotation * a = ai;
                String n( a->entryName() );
                annotationNames.insert( n, new String( n ) );
                ++ai;
            }

            ++mi;
        }
    }

    // Record the unknown used flag and annotation names.

    if ( !flags.isEmpty() ) {
        Dict<String>::Iterator i( flags );
        while ( i ) {
            if ( Flag::id( *i ) == 0 )
                d->flags.append( *i );
            ++i;
        }
    }

    if ( !annotationNames.isEmpty() ) {
        Dict<String>::Iterator i( annotationNames );
        while ( i ) {
            if ( AnnotationName::id( *i ) == 0 )
                d->annotationNames.append( *i );
            ++i;
        }
    }

    // Rows destined for deliveries/delivery_recipients also contain
    // addresses that need to be looked up.

    List<Address> * senders = new List<Address>;
    List<InjectorData::Delivery>::Iterator di( d->deliveries );
    while ( di ) {
        senders->append( di->sender );
        updateAddresses( di->recipients );
        ++di;
    }
    updateAddresses( senders );
}


/*! Adds previously unknown addresses from \a newAddresses to
    d->addresses. */

void Injector::updateAddresses( List<Address> * newAddresses )
{
    List<Address>::Iterator ai( newAddresses );
    while ( ai ) {
        Address * a = ai;
        String k = addressKey( a );
        d->addresses.insert( k, a );
        ++ai;
    }
}


/*! This function creates any unknown names found by
    findDependencies().  It creates up to four subtransactions and
    advances to the next state, trusting Transaction to queue the work
    appropriately.
*/

void Injector::createDependencies()
{
    if ( !d->fields.isEmpty() ) {
        d->fieldNameCreator =
            new FieldNameCreator( d->fields, d->transaction );
        d->fieldNameCreator->execute();
    }

    if ( !d->flags.isEmpty() ) {
        d->flagCreator = new FlagCreator( d->flags, d->transaction );
        d->flagCreator->execute();
    }

    if ( !d->annotationNames.isEmpty() ) {
        d->annotationNameCreator =
            new AnnotationNameCreator( d->annotationNames, d->transaction );
        d->annotationNameCreator->execute();
    }

    AddressCreator * ac = new AddressCreator( &d->addresses, d->transaction );
    ac->execute();

    next();
}


/*! Inserts all unique bodyparts in the messages into the bodyparts
    table, and updates the in-memory objects with the newly-created
    bodyparts.ids. */

void Injector::insertBodyparts()
{
    uint last;

    do {
        last = d->substate;

        if ( d->substate == 0 ) {
            List<Message>::Iterator it( d->messages );
            while ( it ) {
                Message * m = it;
                List<Bodypart>::Iterator bi( m->allBodyparts() );
                while ( bi ) {
                    addBodypartRow( bi );
                    ++bi;
                }
                ++it;
            }

            if ( d->bodyparts.isEmpty() )
                d->substate = 5;
            else
                d->substate++;
        }

        if ( d->substate == 1 ) {
            Query * create =
                new Query( "create temporary table bp ("
                           "bid integer, bytes integer, "
                           "hash text, text text, data bytea, "
                           "i integer, n boolean default 'f')", 0 );

            Query * copy =
                new Query( "copy bp (bytes,hash,text,data,i) "
                           "from stdin with binary", this );

            uint i = 0;
            List<BodypartRow>::Iterator bi( d->bodyparts );
            while ( bi ) {
                BodypartRow * br = bi;

                copy->bind( 1, br->bytes );
                copy->bind( 2, br->hash );
                if ( br->text )
                    copy->bind( 3, *br->text );
                else
                    copy->bindNull( 3 );
                if ( br->data )
                    copy->bind( 4, *br->data );
                else
                    copy->bindNull( 4 );
                copy->bind( 5, i++ );
                copy->submitLine();

                ++bi;
            }

            d->transaction->enqueue( create );
            d->transaction->enqueue( copy );
            d->subtransaction = d->transaction->subTransaction( this );

            d->substate++;
        }

        if ( d->substate == 2 ) {
            Query * setId =
                new Query( "update bp set bid=b.id from bodyparts b where "
                           "bp.hash=b.hash and not bp.text is distinct from "
                           "b.text and not bp.data is distinct from b.data",
                           0 );

            Query * setNew =
                new Query( "update bp set bid=nextval('bodypart_ids')::int, "
                           "n='t' where bid is null", 0 );

            d->insert =
                new Query( "insert into bodyparts "
                           "(id,bytes,hash,text,data) "
                           "select bid,bytes,hash,text,data "
                           "from bp where n", this );

            d->substate++;
            d->subtransaction->enqueue( setId );
            d->subtransaction->enqueue( setNew );
            d->subtransaction->enqueue( d->insert );
            d->subtransaction->execute();
        }

        if ( d->substate == 3 ) {
            if ( !d->insert->done() )
                return;

            if ( d->insert->failed() ) {
                d->subtransaction->restart();
                d->substate = 2;
            }
            else {
                d->substate++;
                d->subtransaction->commit();
                d->select =
                    new Query( "select bid from bp order by i", this );
                d->transaction->enqueue( d->select );
                d->transaction->enqueue( new Query( "drop table bp", 0 ) );
                d->transaction->execute();
            }
        }

        if ( d->substate == 4 ) {
            if ( !d->select->done() )
                return;

            List<BodypartRow>::Iterator bi( d->bodyparts );
            while ( bi ) {
                BodypartRow * br = bi;
                Row * r = d->select->nextRow();
                uint id = r->getInt( "bid" );

                List<Bodypart>::Iterator it( br->bodyparts );
                while ( it ) {
                    it->setId( id );
                    ++it;
                }

                ++bi;
            }
            d->substate++;
        }
    }
    while ( last != d->substate );

    d->select = d->insert = d->copy = 0;
    next();
}


/*! Returns a new Query to select \a num nextval()s as "id" from the
    named \a sequence. */

Query * Injector::selectNextvals( const String & sequence, uint num )
{
    Query * q =
        new Query( "select nextval('" + sequence + "')::int as id "
                   "from generate_series(1,$1)", this );
    q->bind( 1, num );
    return q;
}


/*! Adds \a b to the list of bodyparts if it's not there already. */

void Injector::addBodypartRow( Bodypart * b )
{
    bool storeText = false;
    bool storeData = false;

    // Do we need to store anything at all?

    ContentType *ct = b->contentType();
    if ( ct ) {
        if ( ct->type() == "text" ) {
            storeText = true;
            if ( ct->subtype() == "html" )
                storeData = true;
        }
        else {
            storeData = true;
            if ( ct->type() == "multipart" && ct->subtype() != "signed" )
                storeData = false;
            if ( ct->type() == "message" && ct->subtype() == "rfc822" )
                storeData = false;
        }
    }
    else {
        storeText = true;
    }

    if ( !( storeText || storeData ) )
        return;

    // Yes. What exactly do we need to store?

    String * s;
    String hash;
    String * text = 0;
    String * data = 0;
    PgUtf8Codec u;

    if ( storeText ) {
        text = s = new String( u.fromUnicode( b->text() ) );

        // For certain content types (whose names are "text/html"), we
        // store the contents as data and a plaintext representation as
        // text. (This code may need to move if we want to treat other
        // content types this way. But where to?)

        if ( storeData ) {
            data = s;
            text =
                new String( u.fromUnicode( HTML::asText( b->text() ) ) );
        }
    }
    else {
        data = s = new String( b->data() );
    }
    hash = MD5::hash( *s ).hex();

    // And where does it fit in the list of bodyparts we know already?
    // Either we've seen it before (in which case we add it to the list
    // of bodyparts in the appropriate BodypartRow entry), or we haven't
    // (in which case we add a new BodypartRow).

    BodypartRow * br = d->hashes.find( hash );

    if ( !br ) {
        br = new BodypartRow;
        br->hash = hash;
        br->text = text;
        br->data = data;
        br->bytes = b->numBytes();
        d->hashes.insert( hash, br );
        d->bodyparts.append( br );
    }
    br->bodyparts.append( b );
}


/*! This function inserts rows into the messages table for each Message
    in d->messages, and updates the objects with the newly-created ids.
    It expects to be called repeatedly until it returns true, which it
    does only when the work is done, or an error occurs.
*/

void Injector::selectMessageIds()
{
    if ( !d->select ) {
        d->message = new List<Message>::Iterator( d->messages );
        d->select = selectNextvals( "messages_id_seq", d->messages.count() );
        d->transaction->enqueue( d->select );
        d->transaction->execute();
    }

    if ( !d->copy ) {
        if ( !d->select->done() || d->select->failed() )
            return;

        d->copy = new Query( "copy messages (id,rfc822size,idate) "
                             "from stdin with binary", this );

        while ( d->select->hasResults() ) {
            Message * m = *d->message;
            Row * r = d->select->nextRow();
            m->setDatabaseId( r->getInt( "id" ) );
            d->copy->bind( 1, m->databaseId() );
            if ( !m->hasTrivia() ) {
                m->setRfc822Size( m->rfc822().length() );
                m->setTriviaFetched( true );
            }
            d->copy->bind( 2, m->rfc822Size() );
            d->copy->bind( 2, internalDate( m ) );
            d->copy->submitLine();
            ++(*d->message);
        }

        d->transaction->enqueue( d->copy );
        d->transaction->execute();
    }

    if ( !d->copy->done() )
        return;

    d->select = d->copy = 0;
    next();
}


/*! This private function is responsible for fetching a uid and modseq
    value for each message in each mailbox and incrementing uidnext and
    nextmodseq appropriately.
*/

void Injector::selectUids()
{
    // We are given a number of messages, each of which has its own list
    // of target mailboxes. There may be many messages, but chances are
    // that there are few mailboxes (the overwhelmingly common case is
    // just one mailbox).
    //
    // In principle, we could loop over d->messages/m->mailboxes() as we
    // do elsewhere, enqueue-ing a select/increment for each one. Things
    // would work so long as the increment for one message was executed
    // before the select for the next one. But we don't do that, because
    // then injecting ten thousand messages into one mailbox would need
    // ten thousand selects and, worse still, ten thousand updates too.
    //
    // So we turn the loop inside out, build a list of mailboxes, count
    // the messages to be injected into each one, and increment uidnext
    // and modseq by that number, once per mailbox instead of once per
    // message.
    //
    // To protect against concurrent injection into the same mailboxes,
    // we hold a write lock on the mailboxes during injection; thus, the
    // mailbox list must be sorted, so that the Injectors try to acquire
    // locks in the same order to avoid deadlock.

    if ( !d->queries ) {
        if ( d->mailboxes.isEmpty() ) {
            next();
            return;
        }

        // Lock the mailboxes in ascending order and fetch the uidnext
        // and nextmodseq for each one separately. We can't do this in a
        // single query ("id=any($1)") because that doesn't guarantee to
        // lock the rows in order. The number of mailboxes is unlikely
        // to be large enough for these queries to be a problem.

        d->queries = new List<Query>;
        Map<InjectorData::Mailbox>::Iterator mi( d->mailboxes );
        while ( mi ) {
            Mailbox * mb = mi->mailbox;

            Query * q = new Query( *lockUidnext, this );
            q->bind( 1, mb->id() );
            d->queries->append( q );
            d->transaction->enqueue( q );

            ++mi;
        }

        d->transaction->execute();
    }

    // As the results of each query come in, we identify the
    // corresponding mailbox and assign a uid to each message in it.

    Query * q;
    while ( ( q = d->queries->firstElement() ) != 0 &&
            q->done() )
    {
        if ( !q->hasResults() ) {
            d->failed = true;
            break;
        }

        d->queries->shift();

        Row * r = q->nextRow();
        InjectorData::Mailbox * mb = d->mailboxes.find( r->getInt( "id" ) );
        uint uidnext = r->getInt( "uidnext" );
        int64 nextms = r->getBigint( "nextmodseq" );

        // Until uidnext is a bigint, we're at some risk of running out.

        if ( uidnext > 0x7ff00000 ) {
            Log::Severity level = Log::Error;
            if ( uidnext > 0x7fffff00 )
                level = Log::Disaster;
            log( "Note: Mailbox " + mb->mailbox->name().ascii() +
                 " only has " + fn ( 0x7fffffff - uidnext ) +
                 " more usable UIDs. Please contact info@oryx.com"
                 " to resolve this problem.", level );
        }

        // Any messages in this mailbox are assigned consecutive uids
        // starting with uidnext, but all of them get the same modseq.

        uint n = 0;
        List<Injectee>::Iterator it( mb->messages );
        while ( it ) {
            Injectee * m = it;
            m->setUid( mb->mailbox, uidnext+n );
            m->setModSeq( mb->mailbox, nextms );
            n++;
            ++it;
        }
        if ( n )
            log( "Using UIDs " + fn( uidnext ) + "-" + fn( uidnext + n - 1 ) +
                 " in mailbox " + mb->mailbox->name().utf8() );

        // If we have sessions listening to the mailbox, then they get
        // to see the messages as \Recent. Otherwise, whoever opens
        // the mailbox next will update first_recent.

        bool recentIn = false;
        if ( n && r->getInt( "uidnext" ) == r->getInt( "first_recent" ) ) {
            List<Session>::Iterator si( mb->mailbox->sessions() );
            if ( si ) {
                recentIn = true;
                si->addRecent( uidnext, n );
            }
        }

        // Update uidnext and nextmodseq based on what we did above.

        Query * u;
        if ( recentIn )
            u = new Query( *incrUidnextWithRecent, 0 );
        else
            u = new Query( *incrUidnext, 0 );
        u->bind( 1, mb->mailbox->id() );
        u->bind( 2, n );
        d->transaction->enqueue( u );
        d->transaction->execute();
    }

    if ( d->queries->isEmpty() )
        next();
}


/*! Injects messages into the correct tables. */

void Injector::insertMessages()
{
    Query * qp =
        new Query( "copy part_numbers (message,part,bodypart,bytes,lines) "
                   "from stdin with binary", 0 );
    Query * qh =
        new Query( "copy header_fields (message,part,position,field,value) "
                   "from stdin with binary", 0 );
    Query * qa =
        new Query( "copy address_fields "
                   "(message,part,position,field,number,address) "
                   "from stdin with binary", 0 );
    Query * qd =
        new Query( "copy date_fields (message,value) from stdin", 0 );

    Query * qm =
        new Query( "copy mailbox_messages (mailbox,uid,message,modseq) "
                   "from stdin with binary", 0 );
    Query * qf =
        new Query( "copy flags (mailbox,uid,flag) "
                   "from stdin with binary", 0 );
    Query * qn =
        new Query( "copy annotations (mailbox,uid,name,value,owner) "
                   "from stdin with binary", 0 );
    Query * qw =
        new Query( "copy unparsed_messages (bodypart) "
                   "from stdin with binary", 0 );

    uint flags = 0;
    uint wrapped = 0;
    uint mailboxes = 0;
    uint annotations = 0;

    List<Message>::Iterator it( d->messages );
    while ( it ) {
        Message * m = it;
        uint mid = m->databaseId();

        // The top-level RFC 822 header fields are linked to a special
        // part named "" that does not correspond to any entry in the
        // bodyparts table.

        addPartNumber( qp, mid, "" );
        addHeader( qh, qa, qd, mid, "", m->header() );

        // Since the MIME header fields belonging to the first-child of
        // a single-part Message are appended to the RFC 822 header, we
        // don't need to inject them into the database again.

        bool skip = false;
        ContentType *ct = m->header()->contentType();
        if ( !ct || ct->type() != "multipart" )
            skip = true;

        // Now we insert the headers and bodies of every MIME bodypart.

        List<Bodypart>::Iterator bi( m->allBodyparts() );
        while ( bi ) {
            Bodypart * b = bi;
            String pn( m->partNumber( b ) );

            addPartNumber( qp, mid, pn, b );
            if ( !skip )
                addHeader( qh, qa, qd, mid, pn, b->header() );
            else
                skip = false;

            // message/rfc822 bodyparts get a special part number too.

            if ( b->message() ) {
                String rpn( pn + ".rfc822" );
                addPartNumber( qp, mid, rpn, b );
                addHeader( qh, qa, qd, mid, rpn, b->message()->header() );
            }

            // If the message we're injecting is a wrapper around a
            // message we couldn't parse, record that fact too.

            if ( m->isWrapped() && pn == "2" ) {
                qw->bind( 1, b->id() );
                qw->submitLine();
                wrapped++;
            }

            ++bi;
        }

        ++it;
    }

    List<Injectee>::Iterator imi( d->injectables );
    while ( imi ) {
        Injectee * m = imi;
        ++imi;

        // Then record any mailbox-specific information (e.g. flags).

        List<Mailbox>::Iterator mi( m->mailboxes() );
        while ( mi ) {
            Mailbox *mb = mi;

            mailboxes++;
            addMailbox( qm, m, mb );

            flags += addFlags( qf, m, mb );
            annotations += addAnnotations( qn, m, mb );

            ++mi;
        }
    }

    d->transaction->enqueue( qp );
    d->transaction->enqueue( qh );
    d->transaction->enqueue( qa );
    d->transaction->enqueue( qd );
    if ( mailboxes )
        d->transaction->enqueue( qm );
    if ( flags )
        d->transaction->enqueue( qf );
    if ( annotations )
        d->transaction->enqueue( qn );
    if ( wrapped )
        d->transaction->enqueue( qw );
}


/*! Adds a single part_numbers row for the given \a part number,
    belonging to the message with id \a mid and the bodypart \a b
    (which may be 0) to the query \a q.
*/

void Injector::addPartNumber( Query * q, uint mid, const String &part,
                              Bodypart * b )
{
    q->bind( 1, mid );
    q->bind( 2, part );

    if ( b ) {
        if ( b->id() )
            q->bind( 3, b->id() );
        else
            q->bindNull( 3 );
        q->bind( 4, b->numEncodedBytes() );
        q->bind( 5, b->numEncodedLines() );
    }
    else {
        q->bindNull( 3 );
        q->bindNull( 4 );
        q->bindNull( 5 );
    }

    q->submitLine();
}


/*! Add each field from the header \a h (belonging to the given \a part
    of the message with id \a mid) to one of the queries \a qh, \a qa,
    or \a qd, depending on their type.
*/

void Injector::addHeader( Query * qh, Query * qa, Query * qd, uint mid,
                          const String & part, Header * h )
{
    List< HeaderField >::Iterator it( h->fields() );
    while ( it ) {
        HeaderField * hf = it;

        if ( hf->type() <= HeaderField::LastAddressField ) {
            List< Address > * al = ((AddressField *)hf)->addresses();
            List< Address >::Iterator ai( al );
            uint n = 0;
            while ( ai ) {
                Address * a = d->addresses.find( addressKey( ai ) );
                qa->bind( 1, mid );
                qa->bind( 2, part );
                qa->bind( 3, hf->position() );
                qa->bind( 4, hf->type() );
                qa->bind( 5, n );
                qa->bind( 6, a->id() );
                qa->submitLine();
                ++ai;
                ++n;
            }
        }
        else {
            uint t = 0;
            if ( d->fieldNameCreator )
                t = d->fieldNameCreator->id( hf->name() );
            if ( !t )
                t = FieldName::id( hf->name() );
            if ( !t )
                t = hf->type();

            qh->bind( 1, mid );
            qh->bind( 2, part );
            qh->bind( 3, hf->position() );
            qh->bind( 4, t );
            qh->bind( 5, hf->value() );
            qh->submitLine();

            if ( part.isEmpty() && hf->type() == HeaderField::Date ) {
                DateField * df = (DateField *)hf;
                qd->bind( 1, mid );
                qd->bind( 2, df->date()->isoDateTime() );
                qd->submitLine();
            }
        }

        ++it;
    }
}


/*! Adds a mailbox_messages row for the message \a m in mailbox \a mb to
    the query \a q. */

void Injector::addMailbox( Query * q, Injectee * m, Mailbox * mb )
{
    q->bind( 1, mb->id() );
    q->bind( 2, m->uid( mb ) );
    q->bind( 3, m->databaseId() );
    q->bind( 4, m->modSeq( mb ) );
    q->submitLine();
}


/*! Adds flags rows for the message \a m in mailbox \a mb to the query
    \a q, and returns the number of flags (which may be 0). */

uint Injector::addFlags( Query * q, Injectee * m, Mailbox * mb )
{
    uint n = 0;
    StringList::Iterator it( m->flags( mb ) );
    while ( it ) {
        uint flag = 0;
        if ( d->flagCreator )
            flag = d->flagCreator->id( *it );
        if ( !flag )
            flag = Flag::id( *it );
        n++;
        q->bind( 1, mb->id() );
        q->bind( 2, m->uid( mb ) );
        q->bind( 3, flag );
        q->submitLine();
        ++it;
    }
    return n;
}


/*! Adds annotations rows for the message \a m in mailbox \a mb to the
    query \a q, and returns the number of annotations (may be 0). */

uint Injector::addAnnotations( Query * q, Injectee * m, Mailbox * mb )
{
    uint n = 0;
    List<Annotation>::Iterator ai( m->annotations( mb ) );
    while ( ai ) {
        uint aid = 0;
        if ( d->annotationNameCreator )
            aid = d->annotationNameCreator->id( ai->entryName() );
        if ( !aid )
            aid = AnnotationName::id( ai->entryName() );
        n++;
        q->bind( 1, mb->id() );
        q->bind( 2, m->uid( mb ) );
        q->bind( 3, aid );
        q->bind( 4, ai->value() );
        if ( ai->ownerId() == 0 )
            q->bindNull( 5 );
        else
            q->bind( 5, ai->ownerId() );
        q->submitLine();
        ++ai;
    }
    return n;
}


/*! This private function inserts one row per remote recipient into
    the deliveries table.
*/

void Injector::insertDeliveries()
{
    if ( d->deliveries.isEmpty() )
        return;

    List<InjectorData::Delivery>::Iterator di( d->deliveries );
    while ( di ) {
        Address * sender =
            d->addresses.find( addressKey( di->sender ) );

        Query * q =
            new Query( "insert into deliveries "
                       "(sender,message,injected_at,expires_at) "
                       "values ($1,$2,current_timestamp,"
                       "current_timestamp+interval '2 weeks')", 0 );
        q->bind( 1, sender->id() );
        q->bind( 2, di->message->databaseId() );
        d->transaction->enqueue( q );

        uint n = 0;
        List<Address>::Iterator it( di->recipients );
        while ( it ) {
            Address * a = d->addresses.find( addressKey( it ) );
            Query * q =
                new Query(
                    "insert into delivery_recipients (delivery,recipient) "
                    "values ("
                    "currval(pg_get_serial_sequence('deliveries','id')),"
                    "$1)", 0
                );
            q->bind( 1, a->id() );
            d->transaction->enqueue( q );
            n++;
            ++it;
        }

        log( "Spooling message " + fn( di->message->databaseId() ) +
             " for delivery to " + fn( n ) +
             " remote recipients", Log::Significant );

        ++di;
    }

    d->transaction->enqueue( new Query( "notify deliveries_updated", 0 ) );
}


static String msgid( Message * m ) {
    Header * h = m->header();
    String id;
    if ( h )
        id = h->messageId();
    if ( id.isEmpty() )
        id = "<>";
    return id;
}


/*! Logs a little information about the messages to be injected, and a
    little more for the special case of a single message being injected
    into a single mailbox.
*/

void Injector::logDescription()
{
    List<Injectee>::Iterator im( d->injectables );
    while ( im ) {
        Injectee * m = im;
        ++im;

        String msg( "Injecting message " );
        msg.append( msgid( m ) );
        msg.append( " into " );

        StringList into;
        List<Mailbox>::Iterator mb( m->mailboxes() );
        while ( mb ) {
            into.append( mb->name().utf8() );
            ++mb;
        }
        msg.append( into.join( ", " ) );
        log( msg, Log::Significant );
    }
    List<InjectorData::Delivery>::Iterator dm( d->deliveries );
    while ( dm ) {
        InjectorData::Delivery * del = dm;
        ++dm;

        String msg( "Spooling message " );
        msg.append( msgid( del->message ) );
        msg.append( " from " );
        msg.append( del->sender->lpdomain() );
        msg.append( " to " );

        StringList to;
        List<Address>::Iterator a( del->recipients );
        while ( a ) {
            to.append( a->lpdomain() );
            ++a;
        }
        msg.append( to.join( ", " ) );
        log( msg, Log::Significant );
    }
}


struct MailboxAnnouncement {
    MailboxAnnouncement(): mailbox( 0 ), uidnext( 0 ), nextmodseq( 0 ) {}
    Mailbox * mailbox;
    uint uidnext;
    int64 nextmodseq;
};


/*! Inserts this/these message/s into the MessageCache. If the
    transaction fails, the cache has to be cleared.
*/

void Injector::cache()
{
    List<Injectee>::Iterator it( d->injectables );
    while ( it ) {
        Injectee * m = it;
        ++it;
        m->setBodiesFetched();
        m->setBytesAndLinesFetched();
        m->setAddressesFetched();
        m->setHeadersFetched();
        List<Mailbox>::Iterator mi( m->mailboxes() );
        while ( mi ) {
            Mailbox * mb = mi;
            ++mi;
            uint uid = m->uid( mb );

            MessageCache::insert( mb, uid, m );
        }
    }
}


/*! Returns a sensible internaldate for \a m. If
    Message::internalDate() is not null, it is used, otherwise this
    function tries to obtain a date heuristically.
*/

uint Injector::internalDate( Message * m ) const
{
    if ( !m )
        return 0;
    if ( m->internalDate() )
        return m->internalDate();

    // first: try the most recent received field. this should be
    // very close to the correct internaldate.
    Date id;
    List< HeaderField >::Iterator it( m->header()->fields() );
    while ( it && !id.valid() ) {
        if ( it->type() == HeaderField::Received ) {
            String v = it->rfc822();
            int i = 0;
            while ( v.find( ';', i+1 ) > 0 )
                i = v.find( ';', i+1 );
            if ( i >= 0 )
                id.setRfc822( v.mid( i+1 ) );
        }
        ++it;
    }

    // if that fails, try the message's date.
    if ( !id.valid() ) {
        Date * date = m->header()->date();
        if ( date )
            id.setUnixTime( date->unixTime() ); // ick
    }

    // and if all else fails, now.
    if ( !id.valid() )
        id.setCurrentTime();

    m->setInternalDate( id.unixTime() );
    return id.unixTime();
}


class InjecteeData
    : public Garbage
{
public:
    class Mailbox
        : public Garbage
    {
    public:
        Mailbox()
            : Garbage(),
              mailbox( 0 ), uid( 0 ), modseq( 0 ),
              flags( new StringList ), annotations( new List<Annotation> ) {}
        ::Mailbox * mailbox;
        uint uid;
        int64 modseq;
        StringList * flags;
        List<Annotation> * annotations;
    };

    Map<Mailbox> mailboxes;

    Mailbox * mailbox( ::Mailbox * mb, bool create = false ) {
        Mailbox * m = mailboxes.find( mb->id() );
        if ( m )
            return m;
        if ( !create )
            return 0;
        Mailbox * n = new Mailbox;
        n->mailbox = mb;
        mailboxes.insert( mb->id(), n );
        return n;
    }
};


/*! \class Injectee injector.h
    Represents a message and all its associated mailbox-specific data.

    A message doesn't, by itself, have any mailbox-specific properties
    (uid, flags, annotations, and so on). This subclass ties a message
    to all such (variant, as opposed to the header/bodies) metadata.

    The Injector takes a list of Injectee objects to insert
    into the database.
*/


/*!  Constructs an empty injectable message. The caller has to do
     more.
*/

Injectee::Injectee()
    : Message(), d( new InjecteeData )
{
}


/*! Notifies the message that it has \a uid in \a mailbox. */

void Injectee::setUid( Mailbox * mailbox, uint uid )
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox, true );
    m->uid = uid;
}


/*! Returns what setUid() set for \a mailbox, or 0. */

uint Injectee::uid( Mailbox * mailbox ) const
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox );
    if ( !m )
        return 0;
    return m->uid;
}


/*! Notifies the message that it has \a modseq in \a mailbox. */

void Injectee::setModSeq( Mailbox * mailbox , int64 modseq )
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox, true );
    m->modseq = modseq;
}


/*! Returns what setModSeq() set for \a mailbox, or 0. */

int64 Injectee::modSeq( Mailbox * mailbox ) const
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox );
    if ( !m )
        return 0;
    return m->modseq;
}


/*! Returns a pointer to this message's flags in \a mailbox. The
    return value is never null.
*/

StringList * Injectee::flags( Mailbox * mailbox ) const
{
    return d->mailbox( mailbox, true )->flags;
}


/*! Notifies this message that its flags in \a mailbox are exactly \a
    list.
*/

void Injectee::setFlags( Mailbox * mailbox, const StringList * list )
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox, true );
    m->flags->clear();
    StringList::Iterator i( list );
    while ( i ) {
        m->flags->append( i );
        ++i;
    }
}


/*! Returns a pointer ot this message's annotations in \a
    mailbox. Never returns a null pointer.
*/

List<Annotation> * Injectee::annotations( Mailbox * mailbox ) const
{
    return d->mailbox( mailbox, true )->annotations;
}


/*! Notifies this message that its annotations in \a mailbox are
    exactly \a list.
*/

void Injectee::setAnnotations( Mailbox * mailbox,
                                        List<Annotation> * list )
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox, true );
    m->annotations = list;
}


/*! Allocates and return a sorted list of all Mailbox objects to which
    this Message belongs. setUid() and friends cause the Message to
    belong to one or more Mailbox objects.

    This may return an empty list, but it never returns a null pointer.
*/

List<Mailbox> * Injectee::mailboxes() const
{
    List<Mailbox> * m = new List<Mailbox>;
    Map<InjecteeData::Mailbox>::Iterator i( d->mailboxes );
    while ( i ) {
        m->append( i->mailbox );
        ++i;
    }
    return m;
}


// scans the message for a header field of the appropriate name, and
// returns the field value. The name must not contain the trailing ':'.

static String invalidField( const String & message, const String & name )
{
    uint i = 0;
    while ( i < message.length() ) {
        uint j = i;
        while ( i < message.length() &&
                message[i] != '\n' && message[i] != ':' )
            i++;
        if ( message[i] != ':' )
            return "";
        String h = message.mid( j, i-j ).headerCased();
        i++;
        j = i;
        while ( i < message.length() &&
                ( message[i] != '\n' ||
                  ( message[i] == '\n' &&
                    ( message[i+1] == ' ' || message[i+1] == '\t' ) ) ) )
            i++;
        if ( h == name )
            return message.mid( j, i-j );
        i++;
        if ( message[i] == 10 || message[i] == 13 )
            return "";
    }
    return "";
}


// looks for field in message and adds it to wrapper, if valid.

static void addField( String & wrapper,
                      const String & field, const String & message,
                      const String & dflt = "" )
{
    String value = invalidField( message, field );
    HeaderField * hf = 0;
    if ( !value.isEmpty() )
        hf = HeaderField::create( field, value );
    if ( hf && hf->valid() ) {
        wrapper.append( field );
        wrapper.append( ": " );
        wrapper.append( hf->rfc822() );
        wrapper.append( "\r\n" );
    }
    else if ( !dflt.isEmpty() ) {
        wrapper.append( field );
        wrapper.append( ": " );
        wrapper.append( dflt );
        wrapper.append( "\r\n" );
    }
}


/*! Wraps an unparsable \a message up in another, which contains a short
  \a error message, a little helpful text (or so one hopes), and the
  original message in a blob.

  \a defaultSubject is the subject text to use if no halfway
  sensible text can be extracted from \a message. \a id is used as
  content-disposition filename if supplied and nonempty.
*/

Injectee * Injectee::wrapUnparsableMessage( const String & message,
                                            const String & error,
                                            const String & defaultSubject,
                                            const String & id )
{
    String boundary = acceptableBoundary( message );
    String wrapper;

    addField( wrapper, "From", message,
              "Mail Storage Database <invalid@invalid.invalid>" );

    String subject = invalidField( message, "Subject" );
    HeaderField * hf = 0;
    if ( !subject.isEmpty() )
        hf = HeaderField::create( "Subject", subject );
    uint n = 0;
    while ( n < subject.length() && subject[n] < 127 && subject[n] >= 32 )
        n++;
    if ( hf && hf->valid() && n >= subject.length() )
        subject = "Unparsable message: " + hf->rfc822();
    else
        subject = defaultSubject;
    if ( !subject.isEmpty() )
        wrapper.append( "Subject: " + subject + "\r\n" );

    Date now;
    now.setCurrentTime();
    addField( wrapper, "Date", message, now.rfc822() );
    addField( wrapper, "To", message, "Unknown-Recipients:;" );
    addField( wrapper, "Cc", message );
    addField( wrapper, "References", message );
    addField( wrapper, "In-Reply-To", message );

    wrapper.append( "MIME-Version: 1.0\r\n"
                    "Content-Type: multipart/mixed; boundary=\"" +
                    boundary + "\"\r\n"
                    "\r\n\r\nYou are looking at an easter egg\r\n"
                    "--" + boundary + "\r\n"
                    "Content-Type: text/plain; format=flowed" ); // contd..

    String report = "The appended message was received, "
                    "but could not be stored in the mail \r\n"
                    "database on " + Configuration::hostname() +
                    ".\r\n\r\nThe error detected was: \r\n";
    report.append( error );
    report.append( "\r\n\r\n"
                   "Here are a few header fields from the message "
                   "(possibly corrupted due \r\nto syntax errors):\r\n"
                   "\r\n" );
    if ( !invalidField( message, "From" ).isEmpty() ) {
        report.append( "From:" );
        report.append( invalidField( message, "From" ) );
        report.append( "\r\n" );
    }
    if ( !invalidField( message, "Subject" ).isEmpty() ) {
        report.append( "Subject:" );
        report.append( invalidField( message, "Subject" ) );
        report.append( "\r\n" );
    }
    if ( !invalidField( message, "To" ).isEmpty() ) {
        report.append( "To:" );
        report.append( invalidField( message, "To" ) );
        report.append( "\r\n" );
    }
    report.append( "\r\n"
                   "The complete message as received is appended." );

    // but which charset does the report use?
    n = 0;
    while ( n < report.length() && report[n] < 128 )
        n++;
    if ( n < report.length() )
        wrapper.append( "; charset=unknown-8bit" ); // ... continues c-t
    wrapper.append( "\r\n\r\n" );
    wrapper.append( report );
    wrapper.append( "\r\n\r\n--" + boundary + "\r\n" );
    n = 0;
    while ( n < message.length() &&
            message[n] < 128 &&
            ( message[n] >= 32 ||
              message[n] == 10 ||
              message[n] == 13 ) )
        n++;
    if ( n < message.length() )
        wrapper.append( "Content-Type: application/octet-stream\r\n"
                        "Content-Transfer-Encoding: 8bit\r\n" );
    else
        wrapper.append( "Content-Type: text/plain\r\n" );
    wrapper.append( "Content-Disposition: attachment" );
    if ( !id.isEmpty() ) {
        wrapper.append( "; filename=" );
        if ( id.boring() )
            wrapper.append( id );
        else
            wrapper.append( id.quoted() );
    }
    wrapper.append( "\r\n\r\n" );
    wrapper.append( message );
    wrapper.append( "\r\n--" + boundary + "--\r\n" );

    Injectee * m = new Injectee;
    m->parse( wrapper );
    m->setWrapped( true );
    return m;
}


