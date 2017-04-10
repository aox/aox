// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "injector.h"

#include "map.h"
#include "dict.h"
#include "flag.h"
#include "query.h"
#include "timer.h"
#include "address.h"
#include "message.h"
#include "ustring.h"
#include "mailbox.h"
#include "bodypart.h"
#include "datefield.h"
#include "mimefields.h"
#include "messagecache.h"
#include "helperrowcreator.h"
#include "addressfield.h"
#include "transaction.h"
#include "annotation.h"
#include "postgres.h"
#include "session.h"
#include "scope.h"
#include "graph.h"
#include "html.h"
#include "md5.h"
#include "utf.h"
#include "log.h"
#include "dsn.h"


static GraphableCounter * successes;
static GraphableCounter * failures;


struct BodypartRow
    : public Garbage
{
    BodypartRow()
        : id( 0 ), text( 0 ), data( 0 ), bytes( 0 )
    {}

    uint id;
    EString hash;
    EString * text;
    EString * data;
    uint bytes;
    List<Bodypart> bodyparts;
};


// The following is everything the Injector needs to do its work.

enum State {
    Inactive,
    CreatingMailboxes,
    FindingDependencies,
    CreatingDependencies,
    ConvertingInReplyTo, AddingMoreReferences,
    ConvertingThreadIndex,
    CreatingThreadRoots,
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
          state( Inactive ), failed( false ), retried( 0 ), transaction( 0 ),
          mailboxesCreated( 0 ),
          fieldNameCreator( 0 ), flagCreator( 0 ), annotationNameCreator( 0 ),
          lockUidnext( 0 ), select( 0 ), insert( 0 ),
          substate( 0 ), subtransaction( 0 ),
          findParents( 0 ), findReferences( 0 ),
          findBlah( 0 ), findMessagesInOutlookThreads( 0 ),
          threads( 0 )
    {}

    struct Delivery
        : public Garbage
    {
        Delivery( Injectee * m, Address * a, List<Address> * l, Date * when )
            : message( m ), sender( a ), recipients( l ), later( when )
        {}

        Injectee * message;
        Address * sender;
        List<Address> * recipients;
        Date * later;
    };

    List<Injectee> messages;
    List<Injectee> injectables;
    List<Delivery> deliveries;

    EventHandler * owner;

    State state;
    bool failed;
    bool retried;

    Transaction *transaction;

    EStringList flags;
    EStringList fields;
    EStringList annotationNames;
    UStringList baseSubjects;
    Dict<Address> addresses;
    List< ::Mailbox > * mailboxesCreated;

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

    Query * lockUidnext;
    Query * select;
    Query * insert;

    uint substate;
    Transaction * subtransaction;

    Dict<BodypartRow> hashes;
    List<BodypartRow> bodyparts;

    // for convertInReplyTo()
    Dict< List<Message> > outlooks;
    Map<EString> outlookParentIds;
    Query * findParents;
    Query * findReferences;
    // for convertThreadIndex()
    Query * findBlah;
    Query * findMessagesInOutlookThreads;

    struct ThreadParentInfo
        : public Garbage
    {
    public:
        ThreadParentInfo(): Garbage() {}

        EString references;
        EString messageId;
    };

    struct ThreadInjectee
        : public ThreadRootCreator::Message
    {
    public:
        ThreadInjectee( Injectee * i, Transaction * tr )
            : ThreadRootCreator::Message(), m( i ), t( tr ) {}

        Injectee * m;
        Transaction * t;

        EStringList references() const {
            EStringList result;
            AddressField * r = 0;
            Header * h = m->header();
            if ( h )
                r = h->addressField( HeaderField::References );
            if ( r ) {
                List<Address>::Iterator i( r->addresses() );
                while ( i ) {
                    if ( !i->lpdomain().isEmpty() )
                        result.append( "<" + i->lpdomain() + ">" );
                    ++i;
                }
            }
            return result;
        }

        EString messageId() const {
            Header * h = m->header();
            if ( h )
                return h->messageId();
            return "";
        }
    };

    ThreadRootCreator * threads;
};


/*! \class Injector injector.h
    Stores message objects in the database.

    This class takes a list of Message objects and performs the database
    operations necessary to inject them into their respective mailboxes.
    Injection commences only when execute() is called.
*/


/*! Creates a new Injector to inject messages into the database on
    behalf of the \a owner, which is notified when the injection is
    completed.
*/

Injector::Injector( EventHandler * owner )
    : d( new InjectorData )
{
    if ( !::successes ) {
        ::failures = new GraphableCounter( "injection-errors" );
        ::successes = new GraphableCounter( "messages-injected" );
    }

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
    to the specified \a recipients from the given \a sender, and
    delivered \a later if \a later is non-null.
*/

void Injector::addDelivery( Injectee * message, Address * sender,
                            List<Address> * recipients,
                            Date * later )
{
    d->deliveries.append( new InjectorData::Delivery( message, sender,
                                                      recipients, later ) );
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

EString Injector::error() const
{
    if ( !d->failed )
        return "";

    List<Injectee>::Iterator it( d->messages );
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


/*! Instructs this Injector to use a subtransaction of \a t for all
    its database work.

    Does nothing if the injector already has a transaction.
*/

void Injector::setTransaction( class Transaction * t )
{
    if ( t && !d->transaction )
        d->transaction = t->subTransaction( this );
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
            logDescription();
            if ( d->messages.isEmpty() ) {
                d->state = Done;
            }
            else {
                if ( !d->transaction )
                    d->transaction = new Transaction( this );
                next();
            }
            break;

        case CreatingMailboxes:
            createMailboxes();
            break;

        case FindingDependencies:
            findDependencies();
            next();
            break;

        case CreatingDependencies:
            createDependencies();
            break;

        case ConvertingInReplyTo:
            convertInReplyTo();
            break;

        case AddingMoreReferences:
            addMoreReferences();
            next();
            break;

        case ConvertingThreadIndex:
            convertThreadIndex();
            break;

        case CreatingThreadRoots:
            insertThreadRoots();
            next();
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
            insertThreadIndexes();
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
                Cache::clearAllCaches( false );
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
    }
    while ( last != d->state && d->state != Done && !d->failed );

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
        owner->notify();
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


/*! This private function looks through the list of messages, notes
    what mailboxes are needed, and creates any that do not exist or
    are currently deleted.
*/

void Injector::createMailboxes()
{
    if ( !d->mailboxesCreated ) {
        d->mailboxesCreated = new List<Mailbox>;
        UDict<Mailbox> nonexistent;
        List<Injectee>::Iterator imi( d->injectables );
        while ( imi ) {
            Injectee * m = imi;
            ++imi;

            List<Mailbox>::Iterator mi( m->mailboxes() );
            while ( mi ) {
                Mailbox * mb = mi;
                ++mi;
                if ( mb->deleted() && !nonexistent.contains( mb->name() ) ) {
                    mb->create( d->transaction, 0 );
                    d->mailboxesCreated->append( mb );
                    nonexistent.insert( mb->name(), mb );
                }
            }
        }
        if ( !d->mailboxesCreated->isEmpty() ) {
            Mailbox::refreshMailboxes( d->transaction );
        }
    }
    List<Mailbox>::Iterator m( d->mailboxesCreated );
    while ( m ) {
        if ( m->deleted() )
            return;
        ++m;
    }
    next();
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

    List<Injectee>::Iterator it( d->messages );
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
                EString n( hf->name() );

                if ( hf->type() >= HeaderField::Other &&
                     !seenFields.contains( n ) )
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
            if ( !mb->id() || mb->deleted() )
                log( "Internal error: Mailbox " + mb->name().ascii() +
                     " is not properly known", Log::Disaster );
            InjectorData::Mailbox * mbc = d->mailboxes.find( mb->id() );
            if ( !mbc ) {
                mbc = new InjectorData::Mailbox( mb );
                d->mailboxes.insert( mb->id(), mbc );
            }
            mbc->messages.append( m );

            EStringList::Iterator fi( m->flags( mb ) );
            while ( fi ) {
                d->flags.append( fi );
                ++fi;
            }

            List<Annotation>::Iterator ai( m->annotations( mb ) );
            while ( ai ) {
                Annotation * a = ai;
                d->annotationNames.append( a->entryName() );
                ++ai;
            }

            ++mi;
        }
    }

    d->flags.removeDuplicates();
    d->annotationNames.removeDuplicates( true );
    d->baseSubjects.removeDuplicates( true );

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
        ++ai;
        EString k = AddressCreator::key( a );
        d->addresses.insert( k, a );
    }
}


/*! Ensures that \a a is present in the database after injection. */

void Injector::addAddress( Address * a )
{
    EString k = AddressCreator::key( a );
    d->addresses.insert( k, a );
}


/*! Returns the database ID of \a a, or 0 if this injector hasn't added
    \a a to the database.
*/

uint Injector::addressId( Address * a )
{
    Address * a2 = d->addresses.find( AddressCreator::key( a ) );
    if ( !a2 )
        return 0;
    return a2->id();
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

    if ( !d->addresses.isEmpty() ) {
        AddressCreator * ac
            = new AddressCreator( &d->addresses, d->transaction );
        ac->execute();
    }

    next();
}


/*! Creates a proper References field for any messages which have
    In-Reply-To but not References. This covers some versions of
    Outlook, but not all.
*/

void Injector::convertInReplyTo()
{
    EStringList ids;
    if ( d->outlooks.isEmpty() ) {
        List<Injectee>::Iterator i( d->messages );
        while ( i ) {
            Header * h = i->header();
            if ( !h->field( HeaderField::References ) ) {
                // this mostly catches outlook, but will also catch a
                // few other senders
                EString irt = h->inReplyTo();
                int lt = -1;
                do {
                    // we look at each possible message-id in the
                    // in-reply-to field, not just the first or last
                    lt = irt.find( '<', lt + 1 );
                    int gt = irt.find( '>', lt );
                    if ( lt >= 0 && gt > lt ) {
                        AddressParser ap( irt.mid( lt, gt + 1 - lt ) );
                        ap.assertSingleAddress();
                        if ( ap.error().isEmpty() ) {
                            // there is a message-id, so map from it
                            // to the message(s) that cite it as a
                            // possible parent
                            Address * a = ap.addresses()->firstElement();
                            EString msgid = "<" + a->lpdomain() + ">";
                            if ( !d->outlooks.contains( msgid ) )
                                d->outlooks.insert( msgid, new List<Message> );
                            d->outlooks.find( msgid )->append( i );
                            ids.append( msgid );
                        }
                    }
                } while ( lt > 0 );
            }
            ++i;
        }
        if ( ids.isEmpty() ) {
            // no message-ids found? skip the rest then
            next();
            return;
        }
    }

    if ( !d->findParents ) {
        // send a query to find messages.id for each message-id we
        // found above
        d->findParents = new Query( "", this );
        EString s = "select message, value "
                    "from header_fields "
                    "where field=";
        s.appendNumber( HeaderField::MessageId );
        if ( ids.count() < 100 ) {
            s.append( " and (" );
            bool first = true;
            EStringList::Iterator i( ids );
            uint n = 1;
            while ( i ) {
                // use a series of value=$n instead of value=any($1),
                // because postgres uses a bad plan for the latter.
                if ( !first )
                    s.append( " or " );
                first = false;
                s.append( "value=$" );
                s.appendNumber( n );
                d->findParents->bind( n, *i );
                n++;
                ++i;
            }
            s.append( ")" );
        }
        else {
            s.append( " and value=any($1::text[])" );
            d->findParents->bind( 1, ids );
        }
        d->findParents->setString( s );
        d->transaction->enqueue( d->findParents );
        d->transaction->execute();
    }

    if ( !d->findParents->done() )
        return;

    if ( !d->findReferences ) {
        // once we've found  the message-ids and messages.id, map from
        // the latter to the former so we can retrieve them
        IntegerSet parents;
        while ( d->findParents->hasResults() ) {
            Row * r = d->findParents->nextRow();
            d->outlookParentIds.insert( r->getInt( "message" ),
                                        new EString(r->getEString( "value") ) );
            parents.add( r->getInt( "message" ) );
        }
        if ( parents.isEmpty() ) {
            // those message-ids weren't in the database? ok
            next();
            return;
        }
        // and send a new query to retrieve the References in those messages
        d->findReferences = new Query( "select message, value "
                                       "from header_fields "
                                       "where message=any($1) and field=" +
                                       fn( HeaderField::References ),
                                       this );
        d->findReferences->bind( 1, parents );
        d->transaction->enqueue( d->findReferences );
        d->transaction->execute();
        // it would have been better to send both as one query, but
        // postgres misplanned all our attempts to do that
    }

    while ( d->findReferences->hasResults() ) {
        Row * r = d->findReferences->nextRow();
        // we have the references field, and just for sanity
        EString *msgid = d->outlookParentIds.find( r->getInt( "message" ) );
        if ( msgid ) {
            // we have the message-id and the references field, so
            // make a new child references
            EString ref = r->getEString( "value" );
            ref.append( " " );
            ref.append( *msgid );
            ref = ref.simplified().wrapped( 60, "", " ", false );
            // ... and use that for each of the messages that claim to
            // have this antecedent
            List<Message>::Iterator m( d->outlooks.find( *msgid ) );
            while ( m ) {
                if ( !m->header()->field( HeaderField::References ) )
                    m->header()->add( "References", ref );
                ++m;
            }
        }
    }

    if ( d->findReferences && !d->findReferences->done() )
        return;

    // and then the messages that reply to messages without References
    // (ie. to messages that start a new thread).
    Map<EString>::Iterator id( d->outlookParentIds );
    while ( id ) {
        EString msgid = *id;
        ++id;
        List<Message>::Iterator m( d->outlooks.find( msgid ) );
        while ( m ) {
            if ( !m->header()->field( HeaderField::References ) )
                m->header()->add( "References", msgid );
            ++m;
        }
    }

    next();
}


/*! Like convertInReplyTo(), except that it looks at other messages
    being injected rather than messages already in the database.

    This is a no-op when messages are inserted using SMTP or LMTP, but
    can matter for aoximport.
*/

void Injector::addMoreReferences()
{
    List<Message> queue;
    List<Injectee>::Iterator m( d->messages );
    while ( m ) {
        if ( m->header()->field( HeaderField::References ) )
            queue.append( m );
        ++m;
    }

    while ( !queue.isEmpty() ) {
        Message * parent = queue.shift();
        EString msgid = parent->header()->messageId();
        EString r = parent->header()->
                    field( HeaderField::References )->rfc822( false );
        r.append( " " );
        r.append( msgid );
        r = r.simplified().wrapped( 60, "", " ", false );
        List<Message>::Iterator child( d->outlooks.find( msgid ) );
        while ( child ) {
            if ( !child->header()->field( HeaderField::References ) ) {
                child->header()->add( "References", r );
                queue.append( child );
            }
            ++child;
        }
    }

    d->outlooks.clear();
}


/*! Creates a proper References field for any messages sent by
    Outlook*, ie. having Thread-Index instead of References.
*/

void Injector::convertThreadIndex()
{
    EStringList ids;
    if ( d->outlooks.isEmpty() ) {
        List<Injectee>::Iterator i( d->messages );
        while ( i ) {
            Header * h = i->header();
            if ( !h->field( HeaderField::References ) ) {
                HeaderField * ti = h->field( "Thread-Index" );
                if ( ti ) {
                    EString t = ti->value().utf8().de64();
                    if ( t.length() > 22 ) {
                        t = t.mid( 0, 22 ).e64();
                        ids.append( t );
                        if ( !d->outlooks.contains( t ) )
                            d->outlooks.insert( t, new List<Message> );
                        d->outlooks.find( t )->append( i );
                    }
                }
            }
            ++i;
        }
        if ( ids.isEmpty() ) {
            // no thread-indexes need fixing? skip the rest then
            next();
            return;
        }

        ids.removeDuplicates();
        d->findBlah = new Query( "select message "
                                 "from thread_indexes "
                                 "where thread_index=any($1::text[])", this );
        d->findBlah->bind( 1, ids );
        d->transaction->enqueue( d->findBlah );
        d->transaction->execute();
    }

    if ( !d->findMessagesInOutlookThreads ) {
        if ( !d->findBlah->done() )
            return;

        IntegerSet ante;
        while ( d->findBlah->hasResults() ) {
            Row * r = d->findBlah->nextRow();
            ante.add( r->getInt( "message" ) );
        }

        d->findMessagesInOutlookThreads
            = new Query( "select message, field, value "
                         "from header_fields "
                         "where message=any($1) and part='' and ("
                         "field=" + fn ( HeaderField::MessageId ) + " or "
                         "field=" + fn ( HeaderField::References ) + " or "
                         "field=" + fn ( d->fieldNameCreator->id(
                                             "Thread-Index" ) ) + ") "
                         "order by field desc",
                         this );
        d->findMessagesInOutlookThreads->bind( 1, ante );
        d->transaction->enqueue( d->findMessagesInOutlookThreads );
        d->transaction->execute();
    }

    if ( !d->findMessagesInOutlookThreads->done() )
        return;

    Dict<InjectorData::ThreadParentInfo> antecedents;
    Map<InjectorData::ThreadParentInfo> antecedents2;

    while ( d->findMessagesInOutlookThreads->hasResults() ) {
        Row * r = d->findMessagesInOutlookThreads->nextRow();
        uint m = r->getInt( "message" );
        uint field = r->getInt( "field" );
        InjectorData::ThreadParentInfo * t = antecedents2.find( m );
        if ( field == HeaderField::MessageId ) {
            if ( t )
                t->messageId = r->getEString( "value" );
        }
        else if ( field == HeaderField::References ) {
            if ( t )
                t->references = r->getEString( "value" );
        }
        else if ( !t ) {
            // this will be run first because of "order by field desc" above
            t = new InjectorData::ThreadParentInfo;
            antecedents.insert( r->getEString( "value" ), t );
            log( "antecedent <" + r->getEString( "value" ) + ">", Log::Debug );
            antecedents2.insert( m, t );
        }
    }

    // at this time, we know the message-id, references and
    // thread-index for a bunch of messages. if possible, we want to
    // construct a references field for each message in outlooks now.

    Dict< List<Message> >::Iterator i( d->outlooks );
    while ( i ) {
        List<Message>::Iterator m( *i );
        while ( m ) {
            EString ref;
            // we need to look for the full thread-index (indicating both
            // thread and position within thread)
            HeaderField * ti = m->header()->field( "Thread-Index" );
            EString t = ti->value().utf8().de64();
            // we also look for the parent's and grandparent's thread-index
            EString pt = t.mid( 0, ( (t.length() - 22 - 1) / 5 ) * 5 + 22 );
            InjectorData::ThreadParentInfo * tpi
                = antecedents.find( pt.e64() );
            if ( tpi ) {
                // we have the parent's information
                ref = tpi->references;
                ref.append( " " );
                ref.append( tpi->messageId );
            }
            if ( !tpi && t.length() > 27 ) {
                // we don't, but maybe there is a grandparent?
                EString gt = t.mid( 0, ( (t.length() - 22 - 6) / 5 ) * 5 + 22 );
                log( "considering <" + gt.e64() + ">", Log::Debug );
                tpi = antecedents.find( gt.e64() );
            }
            if ( tpi && ref.isEmpty() ) {
                // we have the grandparent's information, and there is an
                // in-reply-to field, so maybe we have the parent's
                // message-id as well.
                HeaderField * irtf
                    = m->header()->field( HeaderField::InReplyTo );
                EString irt;
                if ( irtf )
                    irt = irtf->rfc822( false );
                int lt = irt.find( '<' );
                int gt = irt.find( '>', lt );
                if ( lt >= 0 && gt > lt ) {
                    AddressParser ap( irt.mid( lt, gt + 1 - lt ) );
                    ap.assertSingleAddress();
                    if ( ap.error().isEmpty() ) {
                        // yes, we have the parent's message-id, or a
                        // plausible message-id anyway.
                        Address * a = ap.addresses()->firstElement();

                        ref = tpi->references;
                        ref.append( " " );
                        ref.append( tpi->messageId );
                        ref.append( " <" );
                        ref.append( a->lpdomain() );
                        ref.append( ">" );
                    }
                }
            }
            if ( !ref.isEmpty() )
                m->header()->add( "References",
                                  ref.simplified().wrapped( 60, "", " ",
                                                            false ) );
            ++m;
        }
        ++i;
    }

    d->outlooks.clear();
    next();
}


/*! Inserts rows into the thread_indexes table, so that
    convertThreadIndex() will have fodder next time it runs.
*/

void Injector::insertThreadIndexes()
{
    Query * q = new Query( "copy thread_indexes (message, thread_index) "
                           "from stdin with binary", 0 );

    List<Injectee>::Iterator m( d->messages );
    while ( m ) {
        HeaderField * ti = m->header()->field( "Thread-Index" );
        if ( ti ) {
            EString t = ti->value().utf8().de64();
            if ( t.length() >= 22 ) {
                q->bind( 1, m->databaseId() );
                q->bind( 2, t.mid( 0, 22 ).e64() );
                q->submitLine();
            }
        }
        ++m;
    }

    d->transaction->enqueue( q );
}


/*! Inserts rows into the thread_roots table, so that insertMessages()
    can reference what it needs to.
*/

void Injector::insertThreadRoots()
{
    List<ThreadRootCreator::Message> * l
        = new List<ThreadRootCreator::Message>;
    List<Injectee>::Iterator i( d->messages );
    while ( i ) {
        l->append( new InjectorData::ThreadInjectee( i, d->transaction ) );
        ++i;
    }
    d->threads = new ThreadRootCreator( l, d->transaction );
    d->threads->execute();
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
            List<Injectee>::Iterator it( d->messages );
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
                // this will fail only if there is some kind of
                // serious, serious failure, the kind where retrying
                // will fail again.
                d->subtransaction->commit();
                d->substate = 100;
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

    d->select = 0;
    d->insert = 0;
    next();
}


/*! Returns a new Query to select \a num nextval()s as "id" from the
    named \a sequence. */

Query * Injector::selectNextvals( const EString & sequence, uint num )
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

    EString * s;
    EString hash;
    EString * text = 0;
    EString * data = 0;
    PgUtf8Codec u;

    if ( storeText ) {
        text = s = new EString( u.fromUnicode( b->text() ) );

        // For certain content types (whose names are "text/html"), we
        // store the contents as data and a plaintext representation as
        // text. (This code may need to move if we want to treat other
        // content types this way. But where to?)

        if ( storeData ) {
            data = s;
            text =
                new EString( u.fromUnicode( HTML::asText( b->text() ) ) );
        }
    }
    else {
        data = s = new EString( b->data() );
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
        d->select = selectNextvals( "messages_id_seq", d->messages.count() );
        d->transaction->enqueue( d->select );
        d->transaction->execute();
    }

    if ( !d->select->done() )
        return;

    if ( d->select->failed() )
        return;

    Query * copy
        = new Query( "copy messages "
                     "(id,rfc822size,idate,thread_root) "
                     "from stdin with binary", this );

    List<Injectee>::Iterator m( d->messages );
    while ( m && d->select->hasResults() ) {
        Row * r = d->select->nextRow();
        m->setDatabaseId( r->getInt( "id" ) );
        copy->bind( 1, m->databaseId() );
        if ( !m->hasTrivia() ) {
            m->setRfc822Size( m->rfc822( false ).length() );
            m->setTriviaFetched( true );
        }
        copy->bind( 2, m->rfc822Size() );
        copy->bind( 3, internalDate( m ) );
        uint tr = d->threads->id( m->header()->messageId() );
        if ( tr ) {
            copy->bind( 4, tr );
            m->setThreadId( tr );
        }
        else {
            copy->bindNull( 4 );
        }
        copy->submitLine();
        ++m;
    }

    d->transaction->enqueue( copy );

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
    // To protect against concurrent injection into the same
    // mailboxes, we hold a write lock on the mailboxes during
    // injection; thus, the Injectors try to acquire locks in the same
    // order to avoid deadlock.

    if ( !d->lockUidnext ) {
        if ( d->mailboxes.isEmpty() ) {
            next();
            return;
        }

        IntegerSet ids;
        Map<InjectorData::Mailbox>::Iterator mi( d->mailboxes );
        while ( mi ) {
            ids.add( mi->mailbox->id() );
            ++mi;
        }

        d->lockUidnext = new Query(
            "select id,uidnext,nextmodseq,first_recent from mailboxes "
            "where id=any($1) order by id for update", this );
        d->lockUidnext->bind( 1, ids );
        d->transaction->enqueue( d->lockUidnext );
        d->transaction->execute();
    }

    while ( d->lockUidnext->hasResults() ) {
        Row * r = d->lockUidnext->nextRow();
        InjectorData::Mailbox * mb = d->mailboxes.find( r->getInt( "id" ) );
        uint uidnext = r->getInt( "uidnext" );
        int64 nextms = r->getBigint( "nextmodseq" );

        if ( uidnext > 0x7ff00000 ) {
            Log::Severity level = Log::Significant;
            if ( uidnext > 0x7fffff00 )
                level = Log::Error;
            log( "Note: Mailbox " + mb->mailbox->name().ascii() +
                 " only has " + fn ( 0x7fffffff - uidnext ) +
                 " more usable UIDs. Please contact info@aox.org"
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
            u = new Query( "update mailboxes "
                           "set uidnext=uidnext+$2,"
                           "nextmodseq=nextmodseq+1,"
                           "first_recent=first_recent+$2 "
                           "where id=$1", 0 );
        else
            u = new Query( "update mailboxes "
                           "set uidnext=uidnext+$2,nextmodseq=nextmodseq+1 "
                           "where id=$1", 0 );
        u->bind( 1, mb->mailbox->id() );
        u->bind( 2, n );
        d->transaction->enqueue( u );
    }

    if ( d->lockUidnext->done() )
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
        new Query( "copy mailbox_messages "
                   "(mailbox,uid,message,modseq,seen,deleted) "
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

    List<Injectee>::Iterator it( d->messages );
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

        Bodypart *bp;
        if ( m->hasPGPsignedPart() ) {
            EString pnr( "raw-pgp-signed" );
            bp = m->children()->shift(); // avoid starting pns with 2
            addPartNumber( qp, mid, pnr, bp );
            ::log( "Injector::insertMessages - added partnumber for raw-signed part: " + pnr, Log::Debug );
        }
        List<Bodypart>::Iterator bi( m->allBodyparts() );
        while ( bi ) {
            Bodypart * b = bi;
            EString pn( m->partNumber( b ) );

            addPartNumber( qp, mid, pn, b );
            if ( !skip )
                addHeader( qh, qa, qd, mid, pn, b->header() );
            else
                skip = false;

            // message/rfc822 bodyparts get a special part number too.

            if ( b->message() ) {
                EString rpn( pn + ".rfc822" );
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
        if ( m->hasPGPsignedPart() ) { // reinsert raw part in children list
            m->children()->prepend( bp );
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

void Injector::addPartNumber( Query * q, uint mid, const EString &part,
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
                          const EString & part, Header * h )
{
    List< HeaderField >::Iterator it( h->fields() );
    while ( it ) {
        HeaderField * hf = it;

        if ( hf->type() <= HeaderField::LastAddressField ) {
            List< Address > * al = ((AddressField *)hf)->addresses();
            List< Address >::Iterator ai( al );
            uint n = 0;
            while ( ai ) {
                qa->bind( 1, mid );
                qa->bind( 2, part );
                qa->bind( 3, hf->position() );
                qa->bind( 4, hf->type() );
                qa->bind( 5, n );
                qa->bind( 6, addressId( ai ) );
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
    if ( !mb->id() ) {
        log( "Asked to inject into synthetic mailbox " + mb->name().ascii() );
        return;
    }
    q->bind( 1, mb->id() );
    q->bind( 2, m->uid( mb ) );
    q->bind( 3, m->databaseId() );
    q->bind( 4, m->modSeq( mb ) );
    EStringList::Iterator i( m->flags( mb ) );
    bool seen = false;
    bool deleted = false;
    while ( i ) {
        uint id = Flag::id( *i );
        ++i;
        if ( Flag::isSeen( id ) )
            seen = true;
        else if ( Flag::isDeleted( id ) )
            deleted = true;
    }
    q->bind( 5, seen );
    q->bind( 6, deleted );
    q->submitLine();
}


/*! Adds flags rows for the message \a m in mailbox \a mb to the query
    \a q, and returns the number of flags (which may be 0). */

uint Injector::addFlags( Query * q, Injectee * m, Mailbox * mb )
{
    uint n = 0;
    EStringList::Iterator it( m->flags( mb ) );
    while ( it ) {
        uint flag = 0;
        if ( d->flagCreator )
            flag = d->flagCreator->id( *it );
        if ( !flag )
            flag = Flag::id( *it );
        if ( !Flag::isSeen( flag ) && !Flag::isDeleted( flag ) ) {
            n++;
            q->bind( 1, mb->id() );
            q->bind( 2, m->uid( mb ) );
            q->bind( 3, flag );
            q->submitLine();
        }
        ++it;
    }
    return n;
}


/*! Adds annotations rows for the message \a m in mailbox \a mb to the
    query \a q, and returns the number of annotations (may be 0). */

uint Injector::addAnnotations( Query * q, Injectee * m, Mailbox * mb )
{
    if ( !d->annotationNameCreator )
        return 0;
    uint n = 0;
    List<Annotation>::Iterator ai( m->annotations( mb ) );
    while ( ai ) {
        uint aid = d->annotationNameCreator->id( ai->entryName() );
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
            d->addresses.find( AddressCreator::key( di->sender ) );

        Query * q =
            new Query( "insert into deliveries "
                       "(sender,message,injected_at,expires_at,deliver_after) "
                       "values ($1,$2,current_timestamp,"
                       "current_timestamp+interval '2 weeks',$3)", 0 );
        q->bind( 1, sender->id() );
        q->bind( 2, di->message->databaseId() );
        if ( di->later )
            q->bind( 3, di->later->isoDateTime() );
        else
            q->bindNull( 3 );
        d->transaction->enqueue( q );

        uint n = 0;
        List<Address>::Iterator it( di->recipients );
        EStringList domains;
        while ( it ) {
            Address * a = d->addresses.find( AddressCreator::key( it ) );
            domains.append( a->domain().utf8().lower() );
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

        Header * h = di->message->header();
        if ( h && h->field( "Auto-Submitted" ) && !di->later ) {
            q = new Query( "update deliveries "
                           "set deliver_after=injected_at+'1 minute'::interval "
                           "where message=$1 and exists ("
                           "(select dr.id from delivery_recipients dr"
                           " join addresses a on (dr.recipient=a.id)"
                           " where dr.action>$2"
                           " and dr.last_attempt > current_timestamp-'1 minute'::interval"
                           " and a.domain=any($3::text[])))", 0 );
            q->bind( 1, di->message->databaseId() );
            q->bind( 2, Recipient::Delayed );
            domains.removeDuplicates();
            q->bind( 3, domains );
            d->transaction->enqueue( q );
        }

        log( "Spooling message " + fn( di->message->databaseId() ) +
             " for delivery to " + fn( n ) +
             " remote recipients", Log::Significant );

        ++di;
    }

    d->transaction->enqueue( new Query( "notify deliveries_updated", 0 ) );
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

        EString msg( "Injecting message " );
        msg.append( m->header()->messageId().forlog() );
        msg.append( " into " );

        EStringList into;
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

        EString msg( "Spooling message " );
        msg.append( del->message->header()->messageId().forlog() );
        msg.append( " from " );
        msg.append( del->sender->lpdomain() );
        msg.append( " to " );

        EStringList to;
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
            EString v = it->rfc822( false );
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
    InjecteeData(): Garbage() {}

    class Mailbox
        : public Garbage
    {
    public:
        Mailbox()
            : Garbage(),
              mailbox( 0 ), uid( 0 ), modseq( 0 ),
              flags( new EStringList ), annotations( new List<Annotation> ) {}
        ::Mailbox * mailbox;
        uint uid;
        int64 modseq;
        EStringList * flags;
        List<Annotation> * annotations;
    };

    List<Mailbox> mailboxes;

    Mailbox * mailbox( ::Mailbox * mb, bool create = false ) {
        if ( mailboxes.firstElement() &&
             mailboxes.firstElement()->mailbox == mb )
            return mailboxes.firstElement();
        List<Mailbox>::Iterator i( mailboxes );
        while ( i && i->mailbox != mb )
            ++i;
        if ( i || !create )
            return i;
        Mailbox * n = new Mailbox;
        n->mailbox = mb;
        mailboxes.append( n );
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

EStringList * Injectee::flags( Mailbox * mailbox ) const
{
    return d->mailbox( mailbox, true )->flags;
}


/*! Notifies this message that its flags in \a mailbox are exactly \a
    list.
*/

void Injectee::setFlags( Mailbox * mailbox, const EStringList * list )
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox, true );
    m->flags->clear();
    EStringList::Iterator i( list );
    while ( i ) {
        m->flags->append( i );
        ++i;
    }
}


/*! Notifies this message that its flags in \a mailbox are exactly \a
    list.

    \a list is a UStringList, but since IMAP does not allow non-ASCII
    flags, any non-ASCII strings in \a list are silently discarded.

*/

void Injectee::setFlags( Mailbox * mailbox, const UStringList * list )
{
    InjecteeData::Mailbox * m = d->mailbox( mailbox, true );
    m->flags->clear();
    UStringList::Iterator i( list );
    while ( i ) {
        if ( i->isAscii() )
            m->flags->append( i->ascii() );
        ++i;
    }
}


/*! Returns a pointer to this message's annotations in \a
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
    List<InjecteeData::Mailbox>::Iterator i( d->mailboxes );
    while ( i ) {
        m->append( i->mailbox );
        ++i;
    }
    return m;
}


// scans the message for a header field of the appropriate name, and
// returns the field value. The name must not contain the trailing ':'.

static EString invalidField( const EString & message, const EString & name )
{
    uint i = 0;
    while ( i < message.length() ) {
        uint j = i;
        while ( i < message.length() &&
                message[i] != '\n' && message[i] != ':' )
            i++;
        if ( message[i] != ':' )
            return "";
        EString h = message.mid( j, i-j ).headerCased();
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

static void addField( EString & wrapper,
                      const EString & field, const EString & message,
                      const EString & dflt = "" )
{
    EString value = invalidField( message, field );
    HeaderField * hf = 0;
    if ( !value.isEmpty() )
        hf = HeaderField::create( field, value );
    if ( hf && hf->valid() ) {
        wrapper.append( field );
        wrapper.append( ": " );
        wrapper.append( hf->rfc822( false ) );
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

Injectee * Injectee::wrapUnparsableMessage( const EString & message,
                                            const EString & error,
                                            const EString & defaultSubject,
                                            const EString & id )
{
    EString boundary = acceptableBoundary( message );
    EString wrapper;

    addField( wrapper, "From", message,
              "Mail Storage Database <invalid@invalid.invalid>" );

    EString subject = invalidField( message, "Subject" );
    HeaderField * hf = 0;
    if ( !subject.isEmpty() )
        hf = HeaderField::create( "Subject", subject );
    uint n = 0;
    while ( n < subject.length() && subject[n] < 127 && subject[n] >= 32 )
        n++;
    if ( hf && hf->valid() && n >= subject.length() )
        subject = "Unparsable message: " + hf->rfc822( false );
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

    EString report = "The appended message was received, "
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
