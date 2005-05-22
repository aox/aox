// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "store.h"

#include "permissions.h"
#include "transaction.h"
#include "imapsession.h"
#include "messageset.h"
#include "mailbox.h"
#include "message.h"
#include "string.h"
#include "query.h"
#include "flag.h"
#include "list.h"
#include "imap.h"


class StoreData {
public:
    StoreData()
        : op( Replace ), silent( false ), uid( false ),
          checkedPermission( false ), fetching( false ),
          transaction( 0 ), flagCreator( 0 )
    {}
    MessageSet s;
    StringList flagNames;

    enum Op { Add, Replace, Remove } op;

    bool silent;
    bool uid;
    bool checkedPermission;

    bool fetching;

    Transaction * transaction;
    List<Flag> flags;
    FlagCreator * flagCreator;
};


/*! \class Store store.h
    Alters message flags (RFC 3501, §6.4.6).

    The Store command is the principal means of altering message flags,
    although Annotate may be able to do the same.
*/

/*! Constructs a Store handler. If \a u is set, the first argument is
    presumed to be a UID set, otherwise it's an MSN set.
*/

Store::Store( bool u )
    : d( new StoreData )
{
    d->uid = u;
}


void Store::parse()
{
    space();
    d->s = set( !d->uid );
    space();

    if ( present( "-" ) )
        d->op = StoreData::Remove;
    else if ( present( "+" ) )
        d->op = StoreData::Add;

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

    end();
}


/*! Stores all the flags, using potentially enormous numbers if
    database queries. The command is kept atomic by the use of a
    Transaction.
*/

void Store::execute()
{
    if ( !d->checkedPermission ) {
        Permissions * p = imap()->session()->permissions();
        if ( !p->ready() )
            return;
        d->checkedPermission = true;
        bool deleted = false;
        bool seen = false;
        bool other = false;
        StringList::Iterator it( d->flagNames );
        while ( it ) {
            if ( *it == "\\deleted" )
                deleted = true;
            else if ( *it == "\\seen" )
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

    if ( !processFlagNames() )
        return;

    if ( !d->transaction ) {
        d->transaction = new Transaction( this );
        switch( d->op ) {
        case StoreData::Replace:
            replaceFlags();
            break;
        case StoreData::Add:
            addFlags();
            break;
        case StoreData::Remove:
            removeFlags();
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
        else {
            recordFlags();
        }
        if ( d->op != StoreData::Replace && !d->silent )
            sendFetches();
        d->fetching = true;
    }

    if ( d->fetching && !d->silent ) {
        if ( d->op == StoreData::Replace )
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


/*! Dumps the command back to the client in the form of fetch
    responses. This function is used to tell the client "yes, your
    store flags command was processed as submitted" without bothering
    the database.

    This function mishandles the "\recent" flag.
*/

void Store::pretendToFetch()
{
    uint max = d->s.count();
    uint i = 1;
    ImapSession * s = imap()->session();
    while ( i <= max ) {
        uint uid = d->s.value( i );
        uint msn = s->msn( uid );
        i++;
        respond( fn( msn ) + " FETCH (UID " +
                 fn( uid ) + " FLAGS (" +
                 d->flagNames.join( " " ) + "))" );
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
                           flags + " and (" + d->s.where() + ")",
                           this );
    q->bind( 1, imap()->session()->mailbox()->id() );
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
                           "mailbox=$2 and (" + w + ") and flag=$1)",
                           h );
    q->bind( 1, f->id() );
    q->bind( 2, m->id() );
    return q;
}


/*! Adds all the necessary flags to the database.
*/

void Store::addFlags()
{
    List<Flag>::Iterator it( d->flags );
    while ( it ) {
        Query * q = addFlagsQuery( it, imap()->session()->mailbox(),
                                   d->s, this );
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
            if ( d->op == StoreData::Replace ) {
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
