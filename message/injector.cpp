// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "injector.h"

#include "dict.h"
#include "flag.h"
#include "query.h"
#include "address.h"
#include "message.h"
#include "ustring.h"
#include "mailbox.h"
#include "bodypart.h"
#include "datefield.h"
#include "fieldcache.h"
#include "mimefields.h"
#include "messagecache.h"
#include "addressfield.h"
#include "transaction.h"
#include "annotation.h"
#include "allocator.h"
#include "session.h"
#include "scope.h"
#include "graph.h"
#include "html.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "dsn.h"


class MidFetcher;
class UidFetcher;
class BidFetcher;
class AddressCreator;
class NewFlagCreator;
class NewAnnotationCreator;
class FieldCreator;


static PreparedStatement *lockUidnext;
static PreparedStatement *incrUidnext;
static PreparedStatement *incrUidnextWithRecent;
static PreparedStatement *idBodypart;
static PreparedStatement *intoBodyparts;

static GraphableCounter * successes;
static GraphableCounter * failures;


// This struct contains the id for a Bodypart, as well as the queries
// used to create and identify it.

struct Bid
    : public Garbage
{
    Bid( Bodypart * b )
        : bodypart( b ), bid( 0 ), insert( 0 ), select( 0 )
    {}

    Bodypart *bodypart;
    uint bid;
    String hash;
    Query * insert;
    Query * select;
};


// These structs represent one part of each entry in the header_fields
// and address_fields tables. (The other part being the message ID.)

struct FieldLink
    : public Garbage
{
    HeaderField *hf;
    String part;
    int position;
};

struct AddressLink
    : public Garbage
{
    AddressLink()
        : address( 0 ), type( HeaderField::From ),
          position( 0 ), number( 0 ) {}

    Address * address;
    HeaderField::Type type;
    String part;
    int position;
    int number;
};


// The following is everything the Injector needs to do its work.

enum State {
    Inactive,
    CreatingFlags, CreatingAnnotationNames, CreatingFields,
    InsertingBodyparts, InsertingAddresses, SelectingUids,
    InsertingMessages,
    LinkingAddresses, LinkingFlags, LinkingAnnotations,
    AwaitingCompletion, Done
};

class InjectorData
    : public Garbage
{
public:
    InjectorData()
        : state( Inactive ), failed( false ),
          owner( 0 ), messages( 0 ), message( 0 ), transaction( 0 ),
          bodyparts( 0 ), midFetcher( 0 ),
          uidFetcher( 0 ), bidFetcher( 0 ), messageId( 0 ),
          addressLinks( 0 ), fieldLinks( 0 ), dateLinks( 0 ),
          otherFields( 0 ), fieldCreator( 0 ), addressCreator( 0 ),
          flagCreator( 0 ), annotationCreator( 0 )
    {}

    State state;

    bool failed;

    EventHandler *owner;
    List<Message> * messages;
    Message * message;

    Transaction *transaction;

    List< Bid > *bodyparts;

    MidFetcher *midFetcher;
    UidFetcher *uidFetcher;
    BidFetcher *bidFetcher;

    uint messageId;

    List< AddressLink > * addressLinks;
    List< FieldLink > * fieldLinks;
    List< FieldLink > * dateLinks;
    StringList * otherFields;

    FieldCreator * fieldCreator;
    AddressCreator * addressCreator;
    NewFlagCreator * flagCreator;
    NewAnnotationCreator * annotationCreator;

    struct Delivery
        : public Garbage
    {
        Delivery( Address * a, List<Address> * l )
            : sender( a ), recipients( l )
        {}

        Address * sender;
        List<Address> * recipients;
    };

    List<Delivery> deliveries;
};


class MidFetcher
    : public EventHandler
{
public:
    Query * insert;
    Query * select;
    EventHandler *owner;
    bool failed;
    bool finished;
    String error;
    uint id;

    MidFetcher( Query * i, Query * s, EventHandler *ev )
        : insert( i ), select( s ), owner( ev ),
          failed( false ), finished( false ), id( 0 )
    {}

    void execute() {
        if ( finished )
            return;

        if ( !select->done() )
            return;

        if ( !select->hasResults() ) {
            failed = true;
            if ( insert->failed() )
                error = insert->error();
            else if ( select->failed() )
                error = select->error();
        }
        else {
            Row * r = select->nextRow();
            id = r->getInt( "id" );
        }

        finished = true;
        owner->execute();
    }

    bool done() const {
        return finished;
    }
};


class UidFetcher
    : public EventHandler
{
public:
    Message * message;
    List<Mailbox>::Iterator *mi;
    List< Query > *queries;
    List< Query > *inserts;
    EventHandler *owner;
    bool failed;
    String error;

    UidFetcher( Message * m, List< Query > *q, EventHandler *ev )
        : message( m ), mi( 0 ), queries( q ), inserts( 0 ),
          owner( ev ), failed( false )
    {}

    void process( Query * q )
    {
        if ( !mi )
            mi = new List<Mailbox>::Iterator( message->mailboxes() );

        Mailbox * m = *mi;

        Row * r = q->nextRow();
        uint uid = r->getInt( "uidnext" );
        int64 ms = r->getBigint( "nextmodseq" );

        message->setUid( m, uid );
        message->setModSeq( m, ms );

        if ( uid > 0x7ff00000 ) {
            Log::Severity level = Log::Error;
            if ( uid > 0x7fffff00 )
                level = Log::Disaster;
            log( "Note: Mailbox " + m->name().ascii() +
                 " only has " + fn ( 0x7fffffff - uid ) +
                 " more usable UIDs. Please contact info@oryx.com"
                 " to resolve this problem.", level );
        }

        Query * u = 0;
        if ( r->getInt( "uidnext" ) == r->getInt( "first_recent" ) ) {
            List<Session>::Iterator i( m->sessions() );
            if ( i ) {
                i->addRecent( uid );
                u = new Query( *incrUidnextWithRecent, 0 );
            }
        }
        if ( !u )
            u = new Query( *incrUidnext, 0 );
        u->bind( 1, m->id() );
        q->transaction()->enqueue( u );
        ++(*mi);
    }

    void execute() {
        Query *q;

        while ( ( q = queries->firstElement() ) != 0 &&
                q->done() )
        {
            queries->shift();

            Query * insert = 0;
            if ( inserts )
                insert = inserts->shift();

            if ( q->hasResults() ) {
                process( q );
            }
            else {
                failed = true;
                if ( insert )
                    error = insert->error();
            }
        }

        if ( queries->isEmpty() )
            owner->execute();
    }

    bool done() const {
        return queries->isEmpty();
    }
};


class BidFetcher
    : public EventHandler
{
public:
    Transaction * transaction;
    Query * look;
    List<Bid> * list;
    EventHandler * owner;
    List<Bid>::Iterator * li;
    uint state;
    uint savepoint;
    bool done;
    bool failed;
    String error;

    BidFetcher( Transaction * t, List<Bid> * l, EventHandler * ev )
        : transaction( t ), look( 0 ), list( l ), owner( ev ),
          li( new List<Bid>::Iterator( list ) ),
          state( 0 ), savepoint( 0 ), done( false ), failed( false )
    {}

    void execute()
    {
        Query * q = 0;

        if ( look ) {
            if ( look->state() == Query::Inactive ) {
                transaction->enqueue( look );
                transaction->execute();
                return;
            }
            if ( !look->done() )
                return;
            // get all the bodyparts rows
            Dict<Row> rows;
            Row * r = 0;
            while ( (r=look->nextRow()) != 0 )
                rows.insert( r->getString( "hash" ), r );
            // then tie each bodyparts row to all the Bodypart objects
            // that have the right hash.
            List<Bid>::Iterator bi( list );
            while ( bi ) {
                r = rows.find( bi->hash );
                if ( r ) {
                    bi->bid = r->getInt( "id" );
                    bi->bodypart->setId( bi->bid );
                }
                ++bi;
            }
        }

        while ( !done && *li ) {
            while ( *li && ( !(*li)->insert || (*li)->bid ) )
                ++(*li);
            if ( !*li )
                break;

            struct Bid * b = *li;
            String s;

            switch ( state ) {
            case 0:
                s.append( "savepoint a" );
                s.append( fn( savepoint ) );
                q = new Query( s, this );
                transaction->enqueue( q );
                transaction->enqueue( b->insert );
                state = 1;
                transaction->execute();
                return;
                break;
            case 1:
                if ( !b->insert->done() )
                    return;
                if ( b->insert->failed() ) {
                    String e( b->insert->error() );
                    if ( !e.contains( "bodyparts_hash_key" ) ) {
                        error = e;
                        done = failed = true;
                        owner->execute();
                        return;
                    }
                    String s( "rollback to a" );
                    s.append( fn( savepoint ) );
                    q = new Query( s, this );
                    transaction->enqueue( q );
                }
                s = "release savepoint a";
                s.append( fn( savepoint ) );
                transaction->enqueue( new Query( s, 0 ) );
                transaction->enqueue( b->select );
                state = 2;
                transaction->execute();
                return;
                break;
            case 2:
                if ( !b->select->done() ) {
                    return;
                }
                else {
                    Row * r = b->select->nextRow();
                    if ( b->select->failed() || !r ) {
                        done = failed = true;
                        error = b->select->error();
                        if ( !r && error.isEmpty() )
                            error = "No matching bodypart found";
                        owner->execute();
                        return;
                    }
                    b->bid = r->getInt( "id" );
                    b->bodypart->setId( b->bid );
                }
                ++(*li);
                state = 0;
                savepoint++;
                break;
            }
        }

        done = true;
        owner->execute();
    }
};


class AddressCreator
    : public EventHandler
{
public:
    int state;
    Query * q;
    Transaction * t;
    List<Address> * addresses;
    EventHandler * owner;
    Dict<Address> unided;
    int savepoint;
    bool failed;
    bool done;

    AddressCreator( Transaction * tr, List<Address> * a, EventHandler * ev )
        : state( 0 ), q( 0 ), t( tr ), addresses( a ), owner( ev ),
          savepoint( 0 ), failed( false ), done( false )
    {}

    void execute();
    void selectAddresses();
    void processAddresses();
    void insertAddresses();
    void processInsert();
};

void AddressCreator::execute()
{
    if ( state == 0 )
        selectAddresses();

    if ( state == 1 )
        processAddresses();

    if ( state == 2 )
        insertAddresses();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        done = true;
        owner->execute();
    }
}

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

void AddressCreator::selectAddresses()
{
    q = new Query( "", this );

    String s( "select id, name, localpart, domain "
              "from addresses where " );

    unided.clear();

    uint i = 0;
    StringList sl;
    List<Address>::Iterator it( addresses );
    while ( it && i < 1024 ) {
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
    }
    else {
        state = 1;
        t->enqueue( q );
        t->execute();
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
            unided.take( addressKey( a ) );
        if ( orig )
            orig->setId( r->getInt( "id" ) );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectAddresses();
    }
    else {
        state = 2;
    }
}

void AddressCreator::insertAddresses()
{
    q = new Query( "savepoint b" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy addresses (name,localpart,domain) "
                   "from stdin with binary", this );
    StringList::Iterator it( unided.keys() );
    while ( it ) {
        Address * a = unided.take( *it );
        q->bind( 1, a->uname(), Query::Binary );
        q->bind( 2, a->localpart(), Query::Binary );
        q->bind( 3, a->domain(), Query::Binary );
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

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "addresses_nld_key" ) ) {
            q = new Query( "rollback to b" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            failed = true;
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint b" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectAddresses();
}


class NewFlagCreator
    : public EventHandler
{
public:
    int state;
    Query * q;
    Transaction * t;
    StringList flags;
    EventHandler * owner;
    Dict<uint> unided;
    int savepoint;
    bool failed;
    bool done;

    NewFlagCreator( Transaction * tr, const StringList & f, EventHandler * ev )
        : state( 0 ), q( 0 ), t( tr ), flags( f ), owner( ev ),
          savepoint( 0 ), failed( false ), done( false )
    {}

    void execute();
    void selectFlags();
    void processFlags();
    void insertFlags();
    void processInsert();
};

void NewFlagCreator::execute()
{
    if ( state == 0 )
        selectFlags();

    if ( state == 1 )
        processFlags();

    if ( state == 2 )
        insertFlags();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        done = true;
        owner->execute();
    }
}

void NewFlagCreator::selectFlags()
{
    q = new Query( "", this );

    String s( "select id, name from flag_names where " );

    unided.clear();

    uint i = 0;
    StringList sl;
    StringList::Iterator it( flags );
    while ( it ) {
        String name( *it );
        if ( Flag::id( name ) == 0 ) {
            ++i;
            String p;
            q->bind( i, name.lower() );
            p.append( "lower(name)=$" );
            p.append( fn( i ) );
            unided.insert( name.lower(), 0 );
            sl.append( p );
        }
        ++it;
    }
    s.append( sl.join( " or " ) );
    q->setString( s );
    q->allowSlowness();

    if ( i == 0 ) {
        state = 4;
    }
    else {
        state = 1;
        t->enqueue( q );
        t->execute();
    }
}

void NewFlagCreator::processFlags()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        String name( r->getString( "name" ) );
        Flag::add( name, r->getInt( "id" ) );
        unided.take( name.lower() );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectFlags();
    }
    else {
        state = 2;
    }
}

void NewFlagCreator::insertFlags()
{
    q = new Query( "savepoint c" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy flag_names (name) from stdin with binary", this );
    StringList::Iterator it( unided.keys() );
    while ( it ) {
        q->bind( 1, *it, Query::Binary );
        q->submitLine();
        ++it;
    }

    state = 3;
    t->enqueue( q );
    t->execute();
}

void NewFlagCreator::processInsert()
{
    if ( !q->done() )
        return;

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "fn_uname" ) ) {
            q = new Query( "rollback to c" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            failed = true;
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint c" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectFlags();
}


class NewAnnotationCreator
    : public EventHandler
{
public:
    int state;
    Query * q;
    Transaction * t;
    StringList names;
    EventHandler * owner;
    Dict<uint> unided;
    int savepoint;
    bool failed;
    bool done;

    NewAnnotationCreator( Transaction * tr, const StringList & f, EventHandler * ev )
        : state( 0 ), q( 0 ), t( tr ), names( f ), owner( ev ),
          savepoint( 0 ), failed( false ), done( false )
    {}

    void execute();
    void selectAnnotations();
    void processAnnotations();
    void insertAnnotations();
    void processInsert();
};

void NewAnnotationCreator::execute()
{
    if ( state == 0 )
        selectAnnotations();

    if ( state == 1 )
        processAnnotations();

    if ( state == 2 )
        insertAnnotations();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        done = true;
        owner->execute();
    }
}

void NewAnnotationCreator::selectAnnotations()
{
    q = new Query( "", this );

    String s( "select id, name from annotation_names where " );

    unided.clear();

    uint i = 0;
    StringList sl;
    StringList::Iterator it( names );
    while ( it ) {
        String name( *it );
        AnnotationName * an =
            AnnotationName::find( name );
        if ( !an || !an->id() ) {
            ++i;
            String p;
            q->bind( i, name );
            p.append( "name=$" );
            p.append( fn( i ) );
            unided.insert( name, 0 );
            sl.append( p );
        }
        ++it;
    }
    s.append( sl.join( " or " ) );
    q->setString( s );
    q->allowSlowness();

    if ( i == 0 ) {
        state = 4;
    }
    else {
        state = 1;
        t->enqueue( q );
        t->execute();
    }
}

void NewAnnotationCreator::processAnnotations()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        uint id = r->getInt( "id" );
        String name( r->getString( "name" ) );
        AnnotationName * an =
            AnnotationName::find( name );
        if ( !an )
            an = new AnnotationName( name, id );
        else
            an->setId( id );
        unided.take( name );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectAnnotations();
    }
    else {
        state = 2;
    }
}

void NewAnnotationCreator::insertAnnotations()
{
    q = new Query( "savepoint d" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy annotation_names (name) "
                   "from stdin with binary", this );
    StringList::Iterator it( unided.keys() );
    while ( it ) {
        q->bind( 1, *it, Query::Binary );
        q->submitLine();
        ++it;
    }

    state = 3;
    t->enqueue( q );
    t->execute();
}

void NewAnnotationCreator::processInsert()
{
    if ( !q->done() )
        return;

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "annotation_names_name_key" ) ) {
            q = new Query( "rollback to d" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            failed = true;
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint d" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectAnnotations();
}


class FieldCreator
    : public EventHandler
{
public:
    int state;
    Query * q;
    Transaction * t;
    StringList fields;
    EventHandler * owner;
    Dict<uint> unided;
    int savepoint;
    bool failed;
    bool done;

    FieldCreator( Transaction * tr, const StringList & f, EventHandler * ev )
        : state( 0 ), q( 0 ), t( tr ), fields( f ), owner( ev ),
          savepoint( 0 ), failed( false ), done( false )
    {}

    void execute();
    void selectFields();
    void processFields();
    void insertFields();
    void processInsert();
};

void FieldCreator::execute()
{
    if ( state == 0 )
        selectFields();

    if ( state == 1 )
        processFields();

    if ( state == 2 )
        insertFields();

    if ( state == 3 )
        processInsert();

    if ( state == 4 ) {
        state = 42;
        done = true;
        owner->execute();
    }
}

void FieldCreator::selectFields()
{
    q = new Query( "", this );

    String s( "select id, name from field_names where " );

    unided.clear();

    uint i = 0;
    StringList sl;
    StringList::Iterator it( fields );
    while ( it ) {
        String name( *it );
        if ( FieldNameCache::translate( name ) == 0 ) {
            ++i;
            String p;
            q->bind( i, name );
            p.append( "name=$" );
            p.append( fn( i ) );
            unided.insert( name, 0 );
            sl.append( p );
        }
        ++it;
    }
    s.append( sl.join( " or " ) );
    q->setString( s );
    q->allowSlowness();

    if ( i == 0 ) {
        state = 4;
    }
    else {
        state = 1;
        t->enqueue( q );
        t->execute();
    }
}

void FieldCreator::processFields()
{
    while ( q->hasResults() ) {
        Row * r = q->nextRow();
        uint id( r->getInt( "id" ) );
        String name( r->getString( "name" ) );
        FieldNameCache::insert( name, id );
        unided.take( name );
    }

    if ( !q->done() )
        return;

    if ( unided.isEmpty() ) {
        state = 0;
        selectFields();
    }
    else {
        state = 2;
    }
}

void FieldCreator::insertFields()
{
    q = new Query( "savepoint e" + fn( savepoint ), this );
    t->enqueue( q );

    q = new Query( "copy field_names (name) from stdin with binary", this );
    StringList::Iterator it( unided.keys() );
    while ( it ) {
        q->bind( 1, *it, Query::Binary );
        q->submitLine();
        ++it;
    }

    state = 3;
    t->enqueue( q );
    t->execute();
}

void FieldCreator::processInsert()
{
    if ( !q->done() )
        return;

    state = 0;
    if ( q->failed() ) {
        if ( q->error().contains( "field_names_name_key" ) ) {
            q = new Query( "rollback to e" + fn( savepoint ), this );
            t->enqueue( q );
            savepoint++;
        }
        else {
            failed = true;
            state = 4;
        }
    }
    else {
        q = new Query( "release savepoint e" + fn( savepoint ), this );
        t->enqueue( q );
    }

    if ( state == 0 )
        selectFields();
}


/*! \class Injector injector.h
    This class delivers a Message to a List of Mailboxes.

    The Injector takes a Message object, and performs all the database
    operations necessary to inject it into each of a List of Mailboxes.
    The message is assumed to be valid. The list of mailboxes must be
    sorted.
*/


/*! This setup function expects to be called by ::main() to perform what
    little initialisation is required by the Injector.
*/

void Injector::setup()
{
    lockUidnext =
        new PreparedStatement(
            "select uidnext,nextmodseq,first_recent from mailboxes "
            "where id=$1 for update"
        );
    Allocator::addEternal( lockUidnext, "lockUidnext" );

    incrUidnext =
        new PreparedStatement(
            "update mailboxes "
            "set uidnext=uidnext+1,nextmodseq=nextmodseq+1 "
            "where id=$1"
        );
    Allocator::addEternal( incrUidnext, "incrUidnext" );

    incrUidnextWithRecent =
        new PreparedStatement(
            "update mailboxes "
            "set uidnext=uidnext+1,"
                 "nextmodseq=nextmodseq+1,"
                 "first_recent=first_recent+1 "
            "where id=$1"
        );
    Allocator::addEternal( incrUidnextWithRecent, "incrUidnext w/recent" );

    idBodypart =
        new PreparedStatement(
            "select id from bodyparts where hash=$1"
        );
    Allocator::addEternal( idBodypart, "idBodypart" );

    intoBodyparts =
        new PreparedStatement(
            "insert into bodyparts (hash,bytes,text,data) "
            "values ($1,$2,$3,$4)"
        );
    Allocator::addEternal( intoBodyparts, "intoBodyparts" );
}


/*! Creates a new Injector to deliver the \a message on behalf of
    the \a owner, which is notified when the injection is completed.
    Message delivery commences when the execute() function is called.
*/

Injector::Injector( Message * message, EventHandler * owner )
    : d( new InjectorData )
{
    if ( !lockUidnext )
        setup();
    d->owner = owner;
    d->message = message;
    d->messages = new List<Message>;
    d->messages->append( message );

    d->bodyparts = new List< Bid >;
    List< Bodypart >::Iterator bi( d->message->allBodyparts() );
    while ( bi ) {
        d->bodyparts->append( new Bid( bi ) );
        ++bi;
    }
}


/*! Cleans up after injection. (We're already pretty clean.) */

Injector::~Injector()
{
}


/*! Notes that the current message must be delivered to the specified
    \a recipients from the given \a sender.
*/

void Injector::addDelivery( Address * sender, List<Address> * recipients )
{
    d->deliveries.append( new InjectorData::Delivery( sender, recipients ) );
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
    if ( !d->message->valid() )
        return d->message->error();
    if ( d->bidFetcher->failed )
        return d->bidFetcher->error;
    if ( !d->transaction )
        return "";
    return d->transaction->error();
}


/*! This function creates and executes the series of database queries
    needed to perform message delivery.
*/

void Injector::execute()
{
    Scope x( log() );

    if ( d->state == Inactive ) {
        if ( !d->message->valid() ) {
            d->failed = true;
            finish();
            return;
        }

        logMessageDetails();

        d->transaction = new Transaction( this );
        d->state = CreatingFlags;
        createFlags();
    }

    if ( d->state == CreatingFlags ) {
        if ( d->flagCreator && !d->flagCreator->done )
            return;

        if ( d->flagCreator && d->flagCreator->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
        else {
            d->state = CreatingAnnotationNames;
            createAnnotationNames();
        }
    }

    if ( d->state == CreatingAnnotationNames ) {
        if ( d->annotationCreator && !d->annotationCreator->done )
            return;

        if ( d->annotationCreator && d->annotationCreator->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
        else {
            d->state = CreatingFields;
            buildFieldLinks();
            createFields();
        }
    }

    if ( d->state == CreatingFields ) {
        if ( d->fieldCreator && !d->fieldCreator->done )
            return;

        if ( d->fieldCreator && d->fieldCreator->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
        else {
            d->state = InsertingBodyparts;
            d->bidFetcher  =
                new BidFetcher( d->transaction, d->bodyparts, this );
            setupBodyparts();
            d->bidFetcher->execute();
        }
    }

    if ( d->state == InsertingBodyparts ) {
        if ( !d->bidFetcher->done )
            return;

        if ( d->bidFetcher->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
        else {
            d->state = InsertingAddresses;
            resolveAddressLinks();
        }
    }

    if ( d->state == InsertingAddresses ) {
        if ( !d->addressCreator->done )
            return;

        if ( d->addressCreator->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
        else {
            selectMessageId();
            selectUids();
            d->transaction->execute();
            d->state = SelectingUids;
        }
    }

    if ( d->state == SelectingUids && !d->transaction->failed() ) {
        // Once we have UIDs for each Mailbox, we can insert rows into
        // messages.

        if ( !d->midFetcher->done() || !d->uidFetcher->done() )
            return;

        if ( d->midFetcher->failed || d->uidFetcher->failed ) {
            d->failed = true;
            d->transaction->rollback();
            d->state = AwaitingCompletion;
        }
        else {
            d->state = InsertingMessages;
        }
    }

    if ( d->state == InsertingMessages && !d->transaction->failed() ) {
        d->messageId = d->midFetcher->id;
        insertMessages();
        linkBodyparts();
        linkHeaderFields();
        linkDates();
        insertDeliveries();
        linkAddresses();

        d->state = LinkingAddresses;
        d->transaction->execute();
    }

    if ( d->state == LinkingAddresses ) {
        List<Mailbox>::Iterator mi( d->message->mailboxes() );
        while ( mi ) {
            Mailbox * m = mi;
            StringList::Iterator i( d->message->flags( m ) );
            while ( i ) {
                if ( Flag::id( *i ) == 0 )
                    return;
                ++i;
            }
            ++mi;
        }
        linkFlags();
        d->state = LinkingFlags;
    }

    if ( d->state == LinkingFlags ) {
        List<Mailbox>::Iterator mi( d->message->mailboxes() );
        while ( mi ) {
            Mailbox * m = mi;
            List<Annotation>::Iterator i( d->message->annotations( m ) );
            while ( i ) {
                if ( i->entryName()->id() == 0 ) {
                    AnnotationName * n;
                    n = AnnotationName::find( i->entryName()->name() );
                    if ( n->id() != 0 )
                        i->setEntryName( n );
                }
                if ( i->entryName()->id() == 0 )
                    return;
                ++i;
            }
            ++mi;
        }
        linkAnnotations();
        handleWrapping();
        d->state = LinkingAnnotations;
    }

    if ( d->state == LinkingAnnotations || d->transaction->failed() ) {
        // Now we just wait for everything to finish.
        if ( d->state < AwaitingCompletion ) {
            d->transaction->enqueue(
                new Query( "notify mailboxes_updated", 0 ) );
            d->transaction->commit();
        }
        d->state = AwaitingCompletion;
    }

    if ( d->state == AwaitingCompletion ) {
        if ( !d->transaction->done() )
            return;
        if ( !::failures ) {
            ::failures = new GraphableCounter( "injection-errors" );
            ::successes = new GraphableCounter( "messages-injected" );
        }

        if ( !d->failed )
            d->failed = d->transaction->failed();

        if ( d->failed ) {
            ::failures->tick();
        }
        else {
            announce();
            ::successes->tick();
        }
        d->state = Done;
        finish();
    }
}


/*! This function notifies the owner of this Injector of its completion.
    It will do so only once.
*/

void Injector::finish()
{
    // XXX: If we fail early in the transaction, we'll continue to
    // be notified of individual query failures. We don't want to
    // pass them on, because d->owner would have killed itself.
    if ( !d->owner )
        return;

    if ( d->failed )
        log( "Injection failed: " + error() );
    else
        log( "Injection succeeded" );
    d->owner->execute();
    d->owner = 0;
}


/*! This private function inserts a new entry into the messages table
    and creates an MidFetcher to fetch the id of the new row.
*/

void Injector::selectMessageId()
{
    Query * insert
        = new Query( "insert into messages (id,rfc822size) "
                     "values (default,$1)", 0 );
    Query * select
        = new Query( "select currval('messages_id_seq')::int as id", 0 );

    insert->bind( 1, d->message->rfc822().length() );

    d->midFetcher = new MidFetcher( insert, select, this );

    insert->setOwner( d->midFetcher );
    select->setOwner( d->midFetcher );

    d->transaction->enqueue( insert );
    d->transaction->enqueue( select );
}


/*! This private function issues queries to retrieve a UID for each of
    the Mailboxes we are delivering the message into, adds each UID to
    d->mailboxes, and informs execute() when it's done.
*/

void Injector::selectUids()
{
    Query *q;
    List< Query > * queries = new List< Query >;
    d->uidFetcher = new UidFetcher( d->message, queries, this );

    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        // We acquire a write lock on our mailbox, and hold it until the
        // entire transaction has committed successfully. We use uidnext
        // in lieu of a UID sequence to serialise Injectors, so that UID
        // announcements are correctly ordered.
        //
        // The mailbox list must be sorted, so that Injectors always try
        // to acquire locks in the same order, thus avoiding deadlocks.

        Mailbox *m = mi;

        q = new Query( *lockUidnext, d->uidFetcher );
        q->bind( 1, m->id() );
        d->transaction->enqueue( q );
        queries->append( q );

        ++mi;
    }
}


/*! This private function builds a list of AddressLinks containing every
    address used in the message, and initiates an AddressCache::lookup()
    after excluding any duplicate addresses. It causes execute() to be
    called when every address in d->addressLinks has been resolved (if
    any need resolving).
*/

void Injector::resolveAddressLinks()
{
    List< Address > * addresses = new List< Address >;
    Dict< Address > unique( 333 );
    Dict< Address > naked( 333 );

    List<AddressLink>::Iterator i( d->addressLinks );
    while ( i ) {
        String k = addressKey( i->address );

        if ( unique.contains( k ) ) {
            i->address = unique.find( k );
        }
        else {
            unique.insert( k, i->address );
            addresses->append( i->address );
            k = i->address->lpdomain();
            naked.insert( k, i->address );
        }

        ++i;
    }

    // if we're also going to insert deliveries rows, and one or more
    // of the addresses aren't in the to/cc fields, make sure we
    // create addresses rows and learn their ids.

    List<InjectorData::Delivery>::Iterator di( d->deliveries );
    while ( di ) {
        List<Address>::Iterator ai( di->recipients );
        while ( ai ) {
            Address * a = ai;
            String k( a->lpdomain() );

            if ( naked.contains( k ) ) {
                Address * same = naked.find( k );
                if ( a != same ) {
                    di->recipients->remove( a );
                    di->recipients->prepend( same );
                }
            }
            else {
                naked.insert( k, a );
                addresses->append( a );
            }
            ++ai;
        }

        String k( di->sender->lpdomain() );
        if ( naked.contains( k ) )
            di->sender = naked.find( k );
        else
            addresses->append( di->sender );

        ++di;
    }

    d->addressCreator =
        new AddressCreator( d->transaction, addresses, this );
    d->addressCreator->execute();
}


/*! This function creates a FieldCreator to create anything in
    d->otherFields that we do not already recognise.
*/

void Injector::createFields()
{
    StringList newFields;

    Dict<int> seen;
    StringList::Iterator it( d->otherFields );
    while ( it ) {
        String n( *it );
        if ( FieldNameCache::translate( n ) == 0 &&
             !seen.contains( n ) )
            newFields.append( n );
        ++it;
    }

    if ( !newFields.isEmpty() ) {
        d->fieldCreator =
            new FieldCreator( d->transaction, newFields, this );
        d->fieldCreator->execute();
    }
}


/*! This private function builds a list of FieldLinks containing every
    header field used in the message, and uses
    FieldNameCache::lookup() to associate each unknown HeaderField
    with an ID. It causes execute() to be called when every field name
    in d->fieldLinks has been resolved.
*/

void Injector::buildFieldLinks()
{
    d->fieldLinks = new List< FieldLink >;
    d->addressLinks = new List< AddressLink >;
    d->dateLinks = new List< FieldLink >;
    d->otherFields = new StringList;

    buildLinksForHeader( d->message->header(), "" );

    // Since the MIME header fields belonging to the first-child of a
    // single-part Message are physically collocated with the RFC 822
    // header, we don't need to inject them into the database again.
    bool skip = false;
    ContentType *ct = d->message->header()->contentType();
    if ( !ct || ct->type() != "multipart" )
        skip = true;

    List< Bid >::Iterator bi( d->bodyparts );
    while ( bi ) {
        Bodypart *bp = bi->bodypart;

        String pn = d->message->partNumber( bp );

        if ( !skip )
            buildLinksForHeader( bp->header(), pn );
        else
            skip = false;

        if ( bp->message() )
            buildLinksForHeader( bp->message()->header(), pn + ".rfc822" );

        ++bi;
    }
}


/*! This private function makes links in d->fieldLinks for each of the
    fields in \a hdr (from the bodypart numbered \a part). It is used
    by buildFieldLinks().
*/

void Injector::buildLinksForHeader( Header *hdr, const String &part )
{
    List< HeaderField >::Iterator it( hdr->fields() );
    while ( it ) {
        HeaderField *hf = it;

        FieldLink *link = new FieldLink;
        link->hf = hf;
        link->part = part;
        link->position = hf->position();

        if ( hf->type() >= HeaderField::Other )
            d->otherFields->append( new String ( hf->name() ) );

        if ( hf->type() > HeaderField::LastAddressField )
            d->fieldLinks->append( link );

        if ( part.isEmpty() && hf->type() == HeaderField::Date )
            d->dateLinks->append( link );

        if ( hf->type() <= HeaderField::LastAddressField ) {
            List< Address > * al = ((AddressField *)hf)->addresses();
            List< Address >::Iterator ai( al );
            uint n = 0;
            while ( ai ) {
                AddressLink * link = new AddressLink;
                link->part = part;
                link->position = hf->position();
                link->type = hf->type();
                link->address = ai;
                link->number = n;
                d->addressLinks->append( link );

                ++n;
                ++ai;
            }
        }

        ++it;
    }
}


/*! This private function looks through d->bodyparts, and fills in the
    INSERT needed to create, and the SELECT needed to identify, every
    storable bodypart in the message. The queries are executed by the
    BidFetcher.
*/

void Injector::setupBodyparts()
{
    StringList hashes;
    List< Bid >::Iterator bi( d->bodyparts );
    while ( bi ) {
        Bodypart *b = bi->bodypart;

        // These decisions should move into Bodypart member functions.

        bool storeText = false;
        bool storeData = false;

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

        if ( storeText || storeData ) {
            PgUtf8Codec u;

            String data;
            if ( storeText )
                data = u.fromUnicode( b->text() );
            else if ( storeData )
                data = b->data();
            bi->hash = MD5::hash( data ).hex();

            Query * i = new Query( *intoBodyparts, d->bidFetcher );
            i->bind( 1, bi->hash );
            i->bind( 2, b->numBytes() );
            hashes.append( bi->hash );

            if ( storeText ) {
                String text( data );

                if ( storeData )
                    text = u.fromUnicode( HTML::asText( b->text() ) );

                i->bind( 3, text, Query::Binary );
            }
            else {
                i->bindNull( 3 );
            }

            if ( storeData )
                i->bind( 4, data, Query::Binary );
            else
                i->bindNull( 4 );

            i->allowFailure();

            bi->insert = i;
            bi->select = new Query( *idBodypart, d->bidFetcher );
            bi->select->bind( 1, bi->hash );
        }

        ++bi;
    }

    if ( hashes.isEmpty() )
        return;

    hashes.removeDuplicates();
    String r = "select id, hash from bodyparts where hash=$";
    uint n = 1;
    d->bidFetcher->look = new Query( "", d->bidFetcher );
    StringList::Iterator h( hashes );
    while ( h ) {
        if ( n > 1 )
            r.append( " or hash=$" );
        r.append( fn( n ) );
        d->bidFetcher->look->bind( n, *h );
        ++n;
        ++h;
    }
    d->bidFetcher->look->setString( r );
}


/*! This private function inserts one row per mailbox into the
    mailbox_messages table.
*/

void Injector::insertMessages()
{
    Query *qm =
        new Query( "copy mailbox_messages "
                   "(mailbox,uid,message,idate,modseq) "
                   "from stdin with binary", 0 );

    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        Mailbox *m = mi;
        uint uid = d->message->uid( m );
        int64 ms = d->message->modSeq( m );

        qm->bind( 1, m->id(), Query::Binary );
        qm->bind( 2, uid, Query::Binary );
        qm->bind( 3, d->messageId, Query::Binary );
        qm->bind( 4, internalDate( m, d->message ), Query::Binary );
        qm->bind( 5, ms, Query::Binary );
        qm->submitLine();

        ++mi;
    }

    if ( !d->message->mailboxes()->isEmpty() )
        d->transaction->enqueue( qm );
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
        Query * q =
            new Query( "insert into deliveries "
                       "(sender,message,injected_at,expires_at) "
                       "values ($1,$2,current_timestamp,"
                       "current_timestamp+interval '2 days')", 0 );
        q->bind( 1, di->sender->id() );
        q->bind( 2, d->messageId );
        d->transaction->enqueue( q );

        uint n = 0;
        List<Address>::Iterator it( di->recipients );
        while ( it ) {
            Query * q =
                new Query(
                    "insert into delivery_recipients (delivery,recipient) "
                    "values ("
                    "currval(pg_get_serial_sequence('deliveries','id')),"
                    "$1)", 0
                );
            q->bind( 1, it->id() );
            d->transaction->enqueue( q );
            n++;
            ++it;
        }

        log( "Spooling message " + fn( d->messageId ) +
             " for delivery to " + fn( n ) +
             " remote recipients", Log::Significant );

        ++di;
    }

    d->transaction->enqueue( new Query( "notify deliveries_updated", 0 ) );
}


/*! This private function inserts rows into the part_numbers table for
    each new message.
*/

void Injector::linkBodyparts()
{
    Query *q =
        new Query( "copy part_numbers (message,part,bodypart,bytes,lines) "
                   "from stdin with binary", 0 );

    insertPartNumber( q, d->messageId, "" );

    List< Bid >::Iterator bi( d->bodyparts );
    while ( bi ) {
        uint bid = bi->bid;
        Bodypart *b = bi->bodypart;

        String pn = d->message->partNumber( b );
        insertPartNumber( q, d->messageId, pn, bid,
                          b->numEncodedBytes(),
                          b->numEncodedLines() );

        if ( b->message() )
            insertPartNumber( q, d->messageId, pn + ".rfc822",
                              bid, b->numEncodedBytes(),
                              b->numEncodedLines() );
        ++bi;
    }

    d->transaction->enqueue( q );
}


/*! This private helper is used by linkBodyparts() to add a single row
    of data to \a q for \a message, \a part, and \a bodypart.
    If bodypart is smaller than 0, a NULL value is inserted instead.
    If \a bytes and \a lines are greater than or equal to 0, their
    values are inserted along with the \a bodypart.
*/

void Injector::insertPartNumber( Query *q, uint message,
                                 const String &part, int bodypart,
                                 int bytes, int lines )
{
    q->bind( 1, message, Query::Binary );
    q->bind( 2, part, Query::Binary );

    if ( bodypart > 0 )
        q->bind( 3, bodypart, Query::Binary );
    else
        q->bindNull( 3 );

    if ( bytes >= 0 )
        q->bind( 4, bytes, Query::Binary );
    else
        q->bindNull( 4 );

    if ( lines >= 0 )
        q->bind( 5, lines, Query::Binary );
    else
        q->bindNull( 5 );

    q->submitLine();
}


/*! This private function inserts entries into the header_fields table
    for each new message.
*/

void Injector::linkHeaderFields()
{
    Query *q =
        new Query( "copy header_fields "
                   "(message,part,position,field,value) "
                   "from stdin with binary", 0 );

    List< FieldLink >::Iterator it( d->fieldLinks );
    while ( it ) {
        FieldLink *link = it;

        uint t = FieldNameCache::translate( link->hf->name() );
        if ( !t )
            t = link->hf->type(); // XXX and what if this too fails?

        q->bind( 1, d->messageId, Query::Binary );
        q->bind( 2, link->part, Query::Binary );
        q->bind( 3, link->position, Query::Binary );
        q->bind( 4, t, Query::Binary );
        q->bind( 5, link->hf->value(), Query::Binary );
        q->submitLine();

        ++it;
    }

    d->transaction->enqueue( q );
}


/*! This private function inserts one entry per AddressLink into the
    address_fields table for each new message.
*/

void Injector::linkAddresses()
{
    Query * q =
        new Query( "copy address_fields "
                   "(message,part,position,field,number,address) "
                   "from stdin with binary", 0 );

    List< AddressLink >::Iterator it( d->addressLinks );
    while ( it ) {
        AddressLink *link = it;

        q->bind( 1, d->messageId, Query::Binary );
        q->bind( 2, link->part, Query::Binary );
        q->bind( 3, link->position, Query::Binary );
        q->bind( 4, link->type, Query::Binary );
        q->bind( 5, link->number, Query::Binary );
        q->bind( 6, link->address->id(), Query::Binary );
        q->submitLine();

        ++it;
    }

    d->transaction->enqueue( q );
}


/*! This private function inserts entries into the date_fields table
    for each new message.
*/

void Injector::linkDates()
{
    List< FieldLink >::Iterator it( d->dateLinks );
    while ( it ) {
        FieldLink * link = it;
        DateField * df = (DateField *)link->hf;

        Query * q =
           new Query( "insert into date_fields (message,value) "
                       "values ($1,$2)", 0 );
        q->bind( 1, d->messageId );
        q->bind( 2, df->date()->isoDateTime() );
        d->transaction->enqueue( q );

        ++it;
    }
}


/*! Logs information about the message to be injected. Some debug,
    some info.
*/

void Injector::logMessageDetails()
{
    String id;
    Header * h = d->message->header();
    if ( h )
        id = h->messageId();
    if ( id.isEmpty() ) {
        log( "Injecting message without message-id", Log::Debug );
        // should we log x-mailer? from? neither?
    }
    else {
        id = id + " ";
    }

    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        Mailbox * m = mi;
        log( "Injecting message " + id + "into mailbox " +
             m->name().ascii(), Log::Significant );
        ++mi;
    }
}


/*! This function announces the injection of a message into the relevant
    mailboxes, using ocd. It should be called only when the Injector has
    completed successfully (done(), but not failed()).

    The Mailbox objects in this process are notified immediately, to
    avoid timing-dependent behaviour within one process.
*/

void Injector::announce()
{
    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        Mailbox * m = mi;
        uint uid = d->message->uid( m );
        int64 ms = d->message->modSeq( m );

        List<Session>::Iterator si( m->sessions() );

        if ( si )
            MessageCache::insert( m, uid, d->message );

        while ( si ) {
            MessageSet dummy;
            dummy.add( uid );
            si->addUnannounced( dummy );
            ++si;
        }

        if ( m->uidnext() <= uid || m->nextModSeq() <= ms )
            m->setUidnextAndNextModSeq( 1+uid, 1+ms );

        ++mi;
    }
}


/*! Starts creating Flag objects for the flags we need to store for
    this message.
*/

void Injector::createFlags()
{
    StringList unknown;

    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        Mailbox * m = mi;
        StringList::Iterator i( d->message->flags( m ) );
        while ( i ) {
            if ( Flag::id( *i ) == 0 )
                unknown.append( *i );
            ++i;
        }
        ++mi;
    }

    if ( !unknown.isEmpty() ) {
        d->flagCreator =
            new NewFlagCreator( d->transaction, unknown, this );
        d->flagCreator->execute();
    }
}


/*! Creates the AnnotationName objects needed to create the annotation
    entries specified with the message.
*/

void Injector::createAnnotationNames()
{
    StringList unknown;

    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        Mailbox * m = mi;
        List<Annotation>::Iterator it( d->message->annotations( m ) );
        while ( it ) {
            if ( !it->entryName()->id() )
                unknown.append( it->entryName()->name() );
            ++it;
        }
        ++mi;
    }

    if ( !unknown.isEmpty() ) {
        d->annotationCreator =
            new NewAnnotationCreator( d->transaction, unknown, this );
        d->annotationCreator->execute();
    }
}


/*! Inserts the flag table entries linking flag_names to the
    mailboxes/uids we occupy.
*/

void Injector::linkFlags()
{
    Query * q =
        new Query( "copy flags (mailbox,uid,flag) "
                   "from stdin with binary", this );

    uint flags = 0;
    List<Mailbox>::Iterator mi( d->message->mailboxes() );
    while ( mi ) {
        Mailbox * m = mi;
        StringList::Iterator i( d->message->flags( m ) );
        while ( i ) {
            flags++;
            q->bind( 1, m->id(), Query::Binary );
            q->bind( 2, d->message->uid( m ), Query::Binary );
            q->bind( 3, Flag::id( *i ), Query::Binary );
            q->submitLine();
            ++i;
        }
        ++mi;
    }

    if ( flags )
        d->transaction->enqueue( q );
}


/*! Inserts the appropriate entries into the annotations table. */

void Injector::linkAnnotations()
{
    Query * q =
        new Query( "copy annotations (mailbox,uid,name,value,owner) "
                   "from stdin with binary", this );

    uint annotations = 0;
    List<Message>::Iterator it( d->messages );
    while ( it ) {
        Message * m = it;
        List<Mailbox>::Iterator mi( m->mailboxes() );
        while ( mi ) {
            Mailbox * mb = mi;
            List<Annotation>::Iterator ai( m->annotations( mb ) );
            while ( ai ) {
                annotations++;
                q->bind( 1, mb->id(), Query::Binary );
                q->bind( 2, m->uid( mb ), Query::Binary );
                q->bind( 3, ai->entryName()->id(), Query::Binary );
                q->bind( 4, ai->value(), Query::Binary );
                if ( ai->ownerId() == 0 )
                    q->bindNull( 5 );
                else
                    q->bind( 5, ai->ownerId(), Query::Binary );
                ++ai;
            }
            ++mi;
        }
        ++it;
    }

    if ( annotations )
        d->transaction->enqueue( q );
}


/*! If any of the messages are wrapped, this function inserts rows into
    the unparsed_messages table for them.
*/

void Injector::handleWrapping()
{
    Query * q =
        new Query( "copy unparsed_messages (bodypart) "
                   "from stdin with binary", this );

    uint wrapped = 0;
    List<Message>::Iterator it( d->messages );
    while ( it ) {
        Message * m = it;
        if ( m->isWrapped() ) {
            wrapped++;

            List<Bodypart>::Iterator bi( m->allBodyparts() );
            while ( bi ) {
                Bodypart * b = bi;
                if ( m->partNumber( b ) == "2" ) {
                    q->bind( 1, b->id() );
                    q->submitLine();
                }
                ++bi;
            }
        }
        ++it;
    }

    if ( wrapped )
        d->transaction->enqueue( q );
}


/*! Returns a sensible internaldate for \a m in \a mb. If
    Message::internalDate() is not null, it is used, otherwise this
    function tries to obtain a date heuristically.
*/

uint Injector::internalDate( Mailbox * mb, Message * m ) const
{
    if ( !m || !mb )
        return 0;
    if ( m->internalDate( mb ) )
        return m->internalDate( mb );

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

    m->setInternalDate( mb, id.unixTime() );
    return id.unixTime();
}
