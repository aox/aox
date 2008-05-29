// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "store.h"

#include "permissions.h"
#include "transaction.h"
#include "imapsession.h"
#include "annotation.h"
#include "messageset.h"
#include "selector.h"
#include "mailbox.h"
#include "message.h"
#include "fetcher.h"
#include "string.h"
#include "query.h"
#include "scope.h"
#include "flag.h"
#include "list.h"
#include "imap.h"
#include "user.h"


class StoreData
    : public Garbage
{
public:
    StoreData()
        : op( ReplaceFlags ), silent( false ), uid( false ),
          checkedPermission( false ),
          unchangedSince( 0 ), seenUnchangedSince( false ),
          modseq( 0 ),
          modSeqQuery( 0 ), obtainModSeq( 0 ), findSet( 0 ),
          transaction( 0 ), flagCreator( 0 ), annotationNameCreator( 0 )
    {}
    MessageSet specified;
    MessageSet s;
    MessageSet expunged;
    MessageSet modified;
    StringList flagNames;

    enum Op { AddFlags, ReplaceFlags, RemoveFlags, ReplaceAnnotations } op;

    bool silent;
    bool uid;
    bool checkedPermission;

    uint unchangedSince;
    bool seenUnchangedSince;
    int64 modseq;
    Query * modSeqQuery;
    Query * obtainModSeq;
    Query * findSet;

    Transaction * transaction;
    List<Flag> flags;
    FlagCreator * flagCreator;
    AnnotationNameCreator * annotationNameCreator;

    List<Annotation> annotations;
};


/*! \class Store store.h
    Alters message flags (RFC 3501 section 6.4.6).

    The Store command is the principal means of altering message
    flags, although Append may be able to do the same.

    The Store object uses setGroup() to allow parallel processing of
    several STORE commands. If the client (incorrectly) sends two
    conflicting commands, e.g. "store 1:* +flags.silent x" and by
    "store 1 -flags.silent x", the commands may be executed in any
    order, and the x flag on message 1 may have any value afterwards.
    Generally, the second command's finished last, because of how the
    database does locking.
*/

/*! Constructs a Store handler. If \a u is set, the first argument is
    presumed to be a UID set, otherwise it's an MSN set.
*/

Store::Store( bool u )
    : d( new StoreData )
{
    d->uid = u;
    setGroup( 3 );
}


/*! Constructs a Store handler which will set the "\seen" flag for the
    messages in \a set within the mailbox currently selected by \a imap,
    and emit flag updates iff \a silent is false.

    This is basically a helper for Fetch, which occasionally needs to
    set "\seen" implicitly. It doesn't have a tag(), so it won't send
    any tagged final response.
*/

Store::Store( IMAP * imap, const MessageSet & set, bool silent )
    : Command( imap ), d( new StoreData )
{
    setLog( new Log( Log::IMAP ) );
    Scope x( log() );
    log( "Store \\seen on " + set.set() );
    d->uid = true;
    d->op = StoreData::AddFlags;
    setGroup( 0 );
    d->specified = set;
    d->silent = silent;
    d->flagNames.append( "\\seen" );
}


void Store::parse()
{
    space();
    d->specified = set( !d->uid );
    d->expunged = imap()->session()->expunged().intersection( d->specified );
    shrink( &d->specified );
    space();

    if ( present( "(" ) ) {
        String modifier = letters( 1, 14 ) .lower();
        while ( ok() && !modifier.isEmpty() ) {
            if ( modifier == "unchangedsince" ) {
                space();
                d->unchangedSince = number();
                if ( d->seenUnchangedSince )
                    error( Bad, "unchangedsince specified twice" );
                d->seenUnchangedSince = true;
                imap()->setClientSupports( IMAP::Condstore );
            }
            else {
                error( Bad, "Unknown search modifier: " + modifier );
            }
            if ( nextChar() == ' ' ) {
                space();
                modifier = letters( 1, 14 ) .lower();
            }
            else {
                modifier = "";
            }
        }
        require( ")" );
        space();
    }

    if ( present( "ANNOTATION (" ) ) {
        d->silent = true;
        bool more = true;
        while ( more ) {
            parseAnnotationEntry();
            more = present( " " );
        }
        require( ")" );
        end();
        d->op = StoreData::ReplaceAnnotations;
    }
    else {
        if ( present( "-" ) )
            d->op = StoreData::RemoveFlags;
        else if ( present( "+" ) )
            d->op = StoreData::AddFlags;

        require( "flags" );
        d->silent = present( ".silent" );
        space();

        if ( present( "()" ) ) {
            // Nothing to do.
        }
        else if ( present( "(" ) ) {
            d->flagNames.append( flag() );
            while ( present( " " ) )
                d->flagNames.append( flag() );
            require( ")" );
        }
        else {
            d->flagNames.append( flag() );
            while ( present( " " ) )
                d->flagNames.append( flag() );
        }
        d->flagNames.removeDuplicates( false );
    }

    end();

    if ( !ok() )
        return;
    String l( "Store " );
    l.append( fn( d->specified.count() ) );
    switch( d->op ) {
    case StoreData::AddFlags:
        l.append( ": add flags " );
        l.append( d->flagNames.join( " " ) );
        break;
    case StoreData::ReplaceFlags:
        l.append( ": replace flags " );
        l.append( d->flagNames.join( " " ) );
        break;
    case StoreData::RemoveFlags:
        l.append( ": remove flags " );
        l.append( d->flagNames.join( " " ) );
        break;
    case StoreData::ReplaceAnnotations:
        l.append( ": replace annotations" );
        List<Annotation>::Iterator it( d->annotations );
        while ( it ) {
            l.append( " " );
            l.append( it->entryName()->name() );
            ++it;
        }
        break;
    }
    log( l );
}




/*! Parses and stores a single annotation entry for later
    processing. Leaves the cursor on the following character
    (space/paren).
*/

void Store::parseAnnotationEntry()
{
    String entry = entryName();;
    if ( entry.startsWith( "/flags/" ) )
        error( Bad, "Cannot set top-level flags using STORE ANNOTATION" );
    if ( entry.contains( "//" ) )
        error( Bad, "Annotation entry names cannot contain //" );
    if ( entry.endsWith( "/" ) )
        error( Bad, "Annotation entry names cannot end with /" );
    space();
    require( "(" );
    if ( !ok() )
        return;
    AnnotationName * n = AnnotationName::find( entry );
    if ( !n )
        n = new AnnotationName( entry );
    bool more = true;
    uint id = imap()->user()->id();
    while ( more ) {
        String attrib = astring();
        bool shared = false;
        if ( attrib.endsWith( ".shared" ) ) {
            shared = true;
            attrib = attrib.mid( 0, attrib.length()-7 );
        }
        else if ( attrib.endsWith( ".priv" ) ) {
            attrib = attrib.mid( 0, attrib.length()-5 );
        }
        else {
            error( Bad, "Must store either .priv or .shared attributes" );
        }
        space();
        String value = string();
        List<Annotation>::Iterator it( d->annotations );
        if ( shared )
            while ( it && ( it->entryName()->name() != entry ||
                            it->ownerId() != id ) )
                ++it;
        else
            while ( it && ( it->entryName()->name() != entry ||
                            it->ownerId() != 0 ) )
                ++it;
        Annotation * a = it;
        if ( !it ) {
            a = new Annotation;
            if ( shared )
                a->setOwnerId( 0 );
            else
                a->setOwnerId( id );
            a->setEntryName( n );
            d->annotations.append( a );
        }
        if ( attrib == "value" )
            a->setValue( value );
        else
            error( Bad, "Unknown attribute: " + attrib );

        more = present( " " );
    }
    require( ")" );
}



/*! Stores all the annotations/flags, using potentially enormous
    numbers of database queries. The command is kept atomic by the use
    of a Transaction.
*/

void Store::execute()
{
    if ( state() != Executing )
        return;

    Mailbox * m = 0;
    if ( imap()->session() )
        m = imap()->session()->mailbox();
    else
        error( No, "Left selected mode during execution" );

    if ( !d->silent && !d->expunged.isEmpty() ) {
        error( No, "Cannot store on expunged messages" );
        return;
    }

    if ( !d->checkedPermission ) {
        if ( d->op == StoreData::ReplaceAnnotations ) {
            bool hasPriv = false;
            bool hasShared = false;
            List<Annotation>::Iterator it( d->annotations );
            while ( it ) {
                if ( it->ownerId() )
                    hasShared = true;
                else
                    hasPriv = true;
                ++it;
            }
            if ( hasPriv )
                requireRight( m, Permissions::Read );
            if ( hasShared )
                requireRight( m, Permissions::WriteSharedAnnotation );
        }
        else {
            bool deleted = false;
            bool seen = false;
            bool other = false;
            StringList::Iterator it( d->flagNames );
            while ( it ) {
                if ( it->lower() == "\\deleted" )
                    deleted = true;
                else if ( it->lower() == "\\seen" )
                    seen = true;
                else
                    other = true;
                ++it;
            }
            if ( seen )
                requireRight( m, Permissions::KeepSeen );
            if ( deleted )
                requireRight( m, Permissions::DeleteMessages );
            if ( other || d->flagNames.isEmpty() )
                requireRight( m, Permissions::Write );
        }
        d->checkedPermission = true;
    }

    if ( !ok() || !permitted() )
        return;

    if ( !d->transaction ) {
        d->transaction = new Transaction( this );

        Selector * work = new Selector;
        work->add( new Selector( d->specified ) );
        Selector * n = new Selector( Selector::Not );
        work->add( n );
        Selector * s = new Selector( Selector::Or );
        n->add( s );
        if ( d->seenUnchangedSince )
            s->add( new Selector( Selector::Modseq, Selector::Larger,
                                  d->unchangedSince ) );
        Selector * a = new Selector( Selector::And );
        s->add( a );
        if ( d->op == StoreData::AddFlags ) {
            StringList::Iterator i( d->flagNames );
            while ( i ) {
                a->add( new Selector( Selector::Flags, Selector::Contains,
                                      *i ) );
                ++i;
            }
        }
        else if ( d->op == StoreData::RemoveFlags ) {
            StringList::Iterator i( d->flagNames );
            while ( i ) {
                n = new Selector( Selector::Not );
                a->add( n );
                n->add( new Selector( Selector::Flags, Selector::Contains,
                                      *i ) );
                ++i;
            }
        }
        // ReplaceFlags can't be optimised because Selector is too
        // weak. ReplaceAnnotations is not worth optimising - noone
        // uses it.
        work->simplify();
        StringList r;
        r.append( "uid" );
        d->findSet = work->query( imap()->user(), m, 0, this, false, &r );
        d->findSet->setString( "select uid from mailbox_messages "
                               "where uid in (" + d->findSet->string() + ")"
                               " for update" );
        d->transaction->enqueue( d->findSet );
        d->transaction->execute();
    }

    while ( d->findSet->hasResults() )
        d->s.add( d->findSet->nextRow()->getInt( "uid" ) );

    if ( d->op == StoreData::ReplaceAnnotations ) {
        if ( !processAnnotationNames() )
            return;
    }
    else {
        if ( !processFlagNames() )
            return;
    }

    if ( !d->findSet->done() )
        return;

    if ( !d->obtainModSeq ) {
        if ( d->seenUnchangedSince ) {
            MessageSet modified;
            modified.add( d->specified );
            modified.remove( d->s );
            if ( !modified.isEmpty() )
                setRespTextCode( "MODIFIED " + modified.set() );
        }

        if ( d->s.isEmpty() ) {
            // no messages need to be changed. we'll just say OK
            log( "No messages need changing", Log::Debug );
            d->transaction->commit();
            finish();
            return;
        }

        d->obtainModSeq
            = new Query( "select nextmodseq from mailboxes "
                         "where id=$1 for update", this );
        d->obtainModSeq->bind( 1, m->id() );
        d->transaction->enqueue( d->obtainModSeq );

        switch( d->op ) {
        case StoreData::ReplaceFlags:
            replaceFlags();
            break;
        case StoreData::AddFlags:
            addFlags();
            break;
        case StoreData::RemoveFlags:
            removeFlags();
            break;
        case StoreData::ReplaceAnnotations:
            replaceAnnotations();
            break;
        }
        d->transaction->execute();
    }

    if ( !d->obtainModSeq->done() )
        return;

    if ( !d->modseq ) {
        Row * r = d->obtainModSeq->nextRow();
        if ( !r ) {
            error( No, "Could not obtain modseq" );
            d->transaction->rollback();
            return;
        }
        d->modseq = r->getBigint( "nextmodseq" );
        Query * q = 0;
        q = new Query( "update mailbox_messages set modseq=$1 "
                       "where mailbox=$2 and uid=any($3)", 0 );
        q->bind( 1, d->modseq );
        q->bind( 2, m->id() );
        q->bind( 3, d->s );
        d->transaction->enqueue( q );

        q = new Query( "update mailboxes set nextmodseq=$1 "
                       "where id=$2", 0 );
        q->bind( 1, d->modseq + 1 );
        q->bind( 2, m->id() );
        d->transaction->enqueue( q );

        d->transaction->enqueue( new Query( "notify mailboxes_updated", 0 ) );
        d->transaction->commit();

        if ( d->silent )
            imap()->session()->ignoreModSeq( d->modseq );
    }

    if ( !d->transaction->done() )
        return;
    if ( d->transaction->failed() ) {
        error( No, "Database error. Rolling transaction back" );
        finish();
        return;
    }

    if ( m->nextModSeq() <= d->modseq )
        m->setNextModSeq( d->modseq + 1 );

    if ( !imap()->session()->initialised() )
        return;

    finish();
}


/*! Adds any necessary flag names to the database and returns true once
    everything is in order.
*/

bool Store::processFlagNames()
{
    StringList::Iterator it( d->flagNames );
    StringList unknown;
    d->flags.clear();
    while ( it ) {
        Flag * f = Flag::find( *it );
        if ( f )
            d->flags.append( f );
        else
            unknown.append( *it );
        ++it;
    }
    if ( unknown.isEmpty() )
        return true;
    else if ( !d->flagCreator )
        d->flagCreator = new FlagCreator( this, unknown );
    return false;
}


/*! Persuades the database to know all the annotation entry names
    we'll be using.
*/

bool Store::processAnnotationNames()
{
    List<Annotation>::Iterator it( d->annotations );
    StringList unknown;
    while ( it ) {
        if ( !it->entryName()->id() )
            unknown.append( it->entryName()->name() );
        ++it;
    }
    if ( unknown.isEmpty() )
        return true;
    if ( !d->annotationNameCreator )
        d->annotationNameCreator = new AnnotationNameCreator( this, unknown );
    return false;

}


/*! Removes the specified flags from the relevant messages in the
    database. If \a opposite, removes all other flags, but leaves the
    specified flags.

    This is a not ideal for the case where a single flag is removed
    from a single messages or from a simple range of messages. In that
    case, we could use a PreparedStatement. Later.
*/

void Store::removeFlags( bool opposite )
{
    List<uint> flags;
    List<Flag>::Iterator it( d->flags );
    while ( it ) {
        flags.append( new uint( it->id() ) );
        ++it;
    }

    String s = "delete from flags where mailbox=$1 and uid=any($2) and ";
    if ( opposite )
        s.append( "not " );
    s.append( "flag=any($3)" );

    Query * q = new Query( s, 0 );
    q->bind( 1, imap()->session()->mailbox()->id() );
    q->bind( 2, d->s );
    q->bind( 3, &flags );
    d->transaction->enqueue( q );
}


/*! Returns a Query which will ensure that all messages in \a s in \a
    m have the \a f flag set. The query will notify event handler \a h
    when it's done.
*/

Query * Store::addFlagsQuery( Flag * f, Mailbox * m, const MessageSet & s,
                              EventHandler * h )
{
    Query * q =
        new Query( "insert into flags (flag,uid,mailbox) "
                   "select $1,mm.uid,$2 from mailbox_messages mm "
                   "left join flags f on "
                   " (mm.mailbox=f.mailbox and mm.uid=f.uid and f.flag=$1) "
                   "where f.flag is null and mm.mailbox=$2 and mm.uid=any($3)",
                   h );
    q->bind( 1, f->id() );
    q->bind( 2, m->id() );
    q->bind( 3, s );
    return q;
}


/*! Adds all the necessary flags to the database.
*/

void Store::addFlags()
{
    Mailbox * m = imap()->session()->mailbox();
    MessageSet s( d->s );

    List<Flag>::Iterator it( d->flags );
    while ( it ) {
        d->transaction->enqueue( addFlagsQuery( it, m, s, 0 ) );
        ++it;
    }
}


/*! Ensures that the specified flags, and no others, are set for all
    the specified messages.
*/

void Store::replaceFlags()
{
    removeFlags( true );
    addFlags();
}


static void bind( Query * q, uint i, const String & n )
{
    if ( n.isEmpty() )
        q->bindNull( i );
    else
        q->bind( i, n );
}


/*! Replaces one or more annotations with the provided replacements. */

void Store::replaceAnnotations()
{
    Mailbox * m = imap()->session()->mailbox();
    MessageSet s( d->s );

    List<Annotation>::Iterator it( d->annotations );
    User * u = imap()->user();
    while ( it ) {
        Query * q;
        if ( it->value().isEmpty() ) {
            String o = "owner=$4";
            if ( !it->ownerId() )
                o = "owner is null";
            q = new Query( "delete from annotations where "
                           "mailbox=$1 and uid=any($2) and "
                           "name=$3 and " + o, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, d->s );
            q->bind( 3, it->entryName()->id() );
            if ( it->ownerId() )
                q->bind( 4, u->id() );
            d->transaction->enqueue( q );
        }
        else {
            String o( "owner=$5" );
            if ( !it->ownerId() )
                o = "owner is null";
            String existing( "where mailbox=$2 and uid=any($3) and "
                             "name=$4 and " + o );
            q = new Query( "update annotations set value=$1 " + existing, 0 );
            bind( q, 1, it->value() );
            q->bind( 2, m->id() );
            q->bind( 3, d->s );
            q->bind( 4, it->entryName()->id() );
            if ( it->ownerId() )
                q->bind( 5, u->id() );
            d->transaction->enqueue( q );

            q = new Query( "insert into annotations "
                           "(mailbox, uid, name, value, owner) "
                           "select $2,uid,$4,$1,$5 "
                           "from mailbox_messages where "
                           "mailbox=$2 and uid=any($3) and uid not in "
                           "(select uid from annotations " + existing + ")",
                           0 );
            bind( q, 1, it->value() );
            q->bind( 2, m->id() );
            q->bind( 3, d->s );
            q->bind( 4, it->entryName()->id() );
            if ( it->ownerId() )
                q->bind( 5, it->ownerId() );
            else
                q->bindNull( 5 );
            d->transaction->enqueue( q );
        }
        ++it;
    }
}


/*! As listMailbox(), but ASCII only. Checks that and emits an error
    if necessary.
*/

String Store::entryName()
{
    UString r = listMailbox();
    if ( !r.isAscii() )
        error( Bad, "Annotation entries are all-ASCII" );
    return r.ascii();
}
