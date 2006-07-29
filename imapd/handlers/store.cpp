// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "store.h"

#include "permissions.h"
#include "transaction.h"
#include "imapsession.h"
#include "annotation.h"
#include "messageset.h"
#include "mailbox.h"
#include "message.h"
#include "string.h"
#include "query.h"
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
          checkedPermission( false ), fetching( false ),
          transaction( 0 ), flagCreator( 0 ), annotationNameCreator( 0 )
    {}
    MessageSet s;
    MessageSet expunged;
    StringList flagNames;

    enum Op { AddFlags, ReplaceFlags, RemoveFlags, ReplaceAnnotations } op;

    bool silent;
    bool uid;
    bool checkedPermission;

    bool fetching;

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


void Store::parse()
{
    space();
    d->s = set( !d->uid );
    d->expunged = imap()->session()->expunged().intersection( d->s );
    shrink( &d->s );
    space();

    if ( present( "ANNOTATION (" ) ) {
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

        if ( present( "(" ) ) {
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
    }

    end();

    if ( !ok() )
        return;
    String l( "Store " );
    l.append( fn( d->s.count() ) );
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
    String entry = listMailbox();
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
    if ( d->s.isEmpty() ) {
        if ( !d->expunged.isEmpty() )
            error( No, "Cannot store on expunged messages" );
        finish();
        return;
    }

    if ( !d->checkedPermission ) {
        Permissions * p = imap()->session()->permissions();
        if ( !p->ready() )
            return;
        d->checkedPermission = true;
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
            if ( hasPriv && !p->allowed( Permissions::Read ) )
                error( No, "Insufficient privileges to "
                       "write private annotations" );
            if ( hasShared &&
                 !p->allowed( Permissions::WriteSharedAnnotation ) )
                error( No, "Insufficient privileges to "
                       "write shared annotations" );
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
            if ( seen && !p->allowed( Permissions::KeepSeen ) )
                error( No, "Insufficient privileges to set \\Seen" );
            else if ( deleted && !p->allowed( Permissions::DeleteMessages ) )
                error( No, "Insufficient privileges to set \\Deleted" );
            else if ( other && !p->allowed( Permissions::Write ) )
                error( No, "Insufficient privileges to set flags" );
            if ( !ok() )
                return;
        }
    }

    if ( d->op == StoreData::ReplaceAnnotations ) {
        if ( !processAnnotationNames() )
            return;
    }
    else {
        if ( !processFlagNames() )
            return;
    }

    if ( !d->transaction ) {
        d->transaction = new Transaction( this );
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
        d->transaction->commit();
    }

    if ( !d->fetching ) {
        if ( !d->transaction->done() )
            return;
        if ( d->transaction->failed() ) {
            error( No, "Database error. Rolling transaction back" );
            finish();
            return;
        }
        else if ( d->op != StoreData::ReplaceAnnotations ) {
            recordFlags();
        }
        if ( !d->silent ) {
            switch( d->op ) {
            case StoreData::AddFlags:
            case StoreData::RemoveFlags:
                sendFetches();
                d->fetching = true;
                break;
            case StoreData::ReplaceFlags:
                d->fetching = true;
                break;
            case StoreData::ReplaceAnnotations:
                break;
            }
        }
    }

    if ( d->fetching && !d->silent ) {
        if ( d->op == StoreData::ReplaceFlags )
            pretendToFetch();
        else if ( !dumpFetchResponses() )
            return;
    }
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


/*! Dumps the command back to the client in the form of fetch
    responses. This function is used to tell the client "yes, your
    store flags command was processed as submitted" without bothering
    the database.
*/

void Store::pretendToFetch()
{
    uint max = d->s.count();
    uint i = 1;
    ImapSession * s = imap()->session();
    String without( " FLAGS (" + d->flagNames.join( " " ) + "))" );
    String with;
    if ( d->flagNames.isEmpty() )
        with = " FLAGS (\\recent))";
    else
        with = " FLAGS (\\recent " + d->flagNames.join( " " ) + "))";
    while ( i <= max ) {
        uint uid = d->s.value( i );
        uint msn = s->msn( uid );
        i++;
        if ( s->isRecent( uid ) )
            respond( fn( msn ) + " FETCH (UID " +
                     fn( uid ) + with );
        else
            respond( fn( msn ) + " FETCH (UID " +
                     fn( uid ) + without );
    }
}


/*! Sends a command to the database to get all the flags for the
    messages we just touched.
*/

void Store::sendFetches()
{
    MessageSet s;
    Mailbox * mb = imap()->session()->mailbox();
    uint i = d->s.count();
    while ( i ) {
        uint uid = d->s.value( i );
        i--;
        Message * m = mb->message( uid, false );
        if ( !m || !m->hasFlags() )
            s.add( uid );
    }
    if ( !s.isEmpty() )
        mb->fetchFlags( s, this );
}


/*! Dumps all the flags for all the relevant messages, as fetched from
    the database or known by earlier commands.  Returns true if it did
    all its work and false if there's more to do.
*/

bool Store::dumpFetchResponses()
{
    bool all = true;
    ImapSession * s = imap()->session();
    Mailbox * mb = s->mailbox();
    while ( all && !d->s.isEmpty() ) {
        uint uid = d->s.value( 1 );
        Message * m = mb->message( uid, false );
        if ( m && m->hasFlags() ) {
            String r;

            if ( s->isRecent( uid ) )
                r = "\\recent";

            List<Flag> * f = m->flags();
            if ( f && !f->isEmpty() ) {
                List<Flag>::Iterator it( f );
                while ( it ) {
                    if ( !r.isEmpty() )
                        r.append( " " );
                    r.append( it->name() );
                    ++it;
                }
            }

            uint msn = s->msn( uid );
            respond( fn( msn ) + " FETCH (UID " +
                     fn( uid ) + " FLAGS (" + r + "))" );
            d->s.remove( uid );
        }
        else {
            all = false;
        }
    }
    return all;
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
    Mailbox * m = imap()->session()->mailbox();
    MessageSet s( d->s );

    if ( m->view() ) {
        s = m->sourceUids( s );
        m = m->source();
    }
    else { 
        s.addGapsFrom( imap()->session()->messages() );
    }

    List<Flag>::Iterator it( d->flags );
    String flags;
    if ( opposite )
        flags = "not";
    String sep( "(flag=" );
    while( it ) {
        flags.append( sep );
        flags.append( fn( it->id() ) );
        if ( sep[0] != ' ' )
            sep = " or flag=";
        ++it;
    }
    flags.append( ")" );

    Query * q = new Query( "delete from flags where mailbox=$1 and " +
                           flags + " and (" + s.where() + ")",
                           this );
    q->bind( 1, m->id() );
    d->transaction->enqueue( q );
}


/*! Returns a Query which will ensure that all messages in \a s in \a
    m have the \a f flag set. The query will notify event handler \a h
    when it's done.

    Like removeFlags(), this could be optimized by the use of
    PreparedStatement for the most common case.
*/

Query * Store::addFlagsQuery( Flag * f, Mailbox * m, const MessageSet & s,
                              EventHandler * h )
{
    String w = s.where();
    Query * q = new Query( "insert into flags (flag,uid,mailbox) "
                           "select $1,uid,$2 from messages where "
                           "mailbox=$2 and (" + w + ") and uid not in "
                           "(select uid from flags where "
                           "flag=$1 and mailbox=$2 and uid>=$3 and uid<=$4)",
                           h );
    q->bind( 1, f->id() );
    q->bind( 2, m->id() );
    q->bind( 3, s.smallest() );
    q->bind( 4, s.largest() );
    return q;
}


/*! Adds all the necessary flags to the database.
*/

void Store::addFlags()
{
    Mailbox * m = imap()->session()->mailbox();
    MessageSet s( d->s );

    if ( m->view() ) {
        s = m->sourceUids( s );
        m = m->source();
    }
    else { 
        s.addGapsFrom( imap()->session()->messages() );
    }

    List<Flag>::Iterator it( d->flags );
    while ( it ) {
        Query * q = addFlagsQuery( it, m, s, this );
        d->transaction->enqueue( q );
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


/*! Records the flag changes in the affected messags. In some cases,
    this just dumps the cached flags, in others it updates the cache.
*/

void Store::recordFlags()
{
    Mailbox * mb = imap()->session()->mailbox();
    uint i = d->s.count();
    while ( i ) {
        uint uid = d->s.value( i );
        i--;
        Message * m = mb->message( uid, false );
        if ( m && m->hasFlags() ) {
            if ( d->op == StoreData::ReplaceFlags ) {
                // we have a correct value, so remember it
                m->setFlagsFetched( true );
                List<Flag> * current = m->flags();
                current->clear();
                List<Flag>::Iterator it( d->flags );
                while ( it ) {
                    current->append( it );
                    ++it;
                }
            }
            else {
                m->setFlagsFetched( false );
            }
        }
    }
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

    if ( m->view() ) {
        s = m->sourceUids( s );
        m = m->source();
    }
    else {
        s.addGapsFrom( imap()->session()->messages() );
    }
        

    List<Annotation>::Iterator it( d->annotations );
    String w = s.where();
    User * u = imap()->user();
    while ( it ) {
        Query * q;
        if ( it->value().isEmpty() ) {
            String o = "owner=$3";
            if ( !it->ownerId() )
                o = "owner is null";
            q = new Query( "delete from annotations where "
                                   "mailbox=$1 and (" + w + ") and "
                                   "name=$2 and " + o, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, it->entryName()->id() );
            if ( it->ownerId() )
                q->bind( 3, u->id() );
            d->transaction->enqueue( q );
        }
        else {
            String o( "owner=$4" );
            if ( !it->ownerId() )
                o = "owner is null";
            String existing( "where mailbox=$1 and (" + w + ") and "
                             "name=$2 and " + o );
            q = new Query( "update annotations set value=$3 " + existing, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, it->entryName()->id() );
            bind( q, 3, it->value() );
            if ( it->ownerId() )
                q->bind( 4, u->id() );
            d->transaction->enqueue( q );

            q = new Query( "insert into annotations "
                           "(mailbox, uid, name, value, owner) "
                           "select $1,uid,$2,$3,$4 from messages where "
                           "mailbox=$1 and (" + w + ") and uid not in "
                           "(select uid from annotations " + existing + ")",
                           0 );
            q->bind( 1, m->id() );
            q->bind( 2, it->entryName()->id() );
            bind( q, 3, it->value() );
            if ( it->ownerId() )
                q->bind( 4, it->ownerId() );
            else
                q->bindNull( 4 );
            d->transaction->enqueue( q );
        }
        ++it;
    }
}
