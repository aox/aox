#include "store.h"

#include "messageset.h"
#include "string.h"
#include "list.h"
#include "messageset.h"
#include "transaction.h"
#include "query.h"
#include "flag.h"
#include "imap.h"
#include "imapsession.h"
#include "mailbox.h"


class StoreData
{
public:
    StoreData() : op( Replace ),
                  silent( false ), uid( false ),
                  modifyAnsweredFlag( false ),
                  modifyFlaggedFlag( false ),
                  modifyDeletedFlag( false ),
                  modifySeenFlag( false ),
                  modifyDraftFlag( false ),
                  system( false ),
                  fetching( false ),
                  transaction( 0 ),
                  fetchSystem( 0 ), fetchExtra( 0 ),
                  flagCreator( 0 )
        {}
    MessageSet s;
    StringList flagNames;

    enum Op { Add, Replace, Remove } op;

    bool silent;
    bool uid;

    bool modifyAnsweredFlag;
    bool modifyFlaggedFlag;
    bool modifyDeletedFlag;
    bool modifySeenFlag;
    bool modifyDraftFlag;
    bool system;

    bool fetching;

    Transaction * transaction;
    Query * fetchSystem;
    Query * fetchExtra;
    List<Flag> extra;
    FlagCreator * flagCreator;
};


/*! \class Store store.h
    Alters message flags (RFC 3501, §6.4.6).

    The Store command is the principal means of altering message flags,
    although Annotate may be able to do the same.
*/

/*!  Constructs a Store handler. If \a u is set, the first argument is
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
    d->s = set( d->uid );
    space();

    if ( present( "-" ) )
        d->op = StoreData::Remove;
    else if ( present( "+" ) )
        d->op = StoreData::Add;

    require( "flags" );
    d->silent = present( ".silent" );
    space();

    if ( present( "(" ) ) {
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
    if ( !addExtraFlagNames() )
        return;

    if ( !d->transaction ) {
        d->transaction = new Transaction( this );
        splitSystemExtra();
        updateSystemFlags();
        killSuperfluousRows();
        addExtraFlags();
        d->transaction->execute();
    }

    if ( !d->fetching ) {
        if ( !d->transaction->done() )
            return;
        if ( d->transaction->failed() ) {
            error( No, "Database error. Rolling transaction back" );
            d->transaction->rollback();
            setState( Finished );
            return;
        }
        d->transaction->commit();
        d->fetching = true;
    }

    if ( d->fetching && !d->silent ) {
        if ( d->op == StoreData::Replace ) {
            pretendToFetch();
        }
        else {
            if ( !d->fetchSystem )
                sendFetches();
            if ( !dumpFetchResponses() )
                return;
        }
    }
    respond( "OK" );
    setState( Finished );
}


/*! Adds any necessary flag names to the database and return true once
    everything is in order.
*/

bool Store::addExtraFlagNames()
{
    StringList::Iterator it = d->flagNames.first();
    StringList unknown;
    while ( it ) {
        Flag * f = Flag::find( *it );
        if ( (*it)[0] != '\\' && !f )
            unknown.append( *it );
        ++it;
    }
    if ( unknown.isEmpty() )
        return true;
    else if ( !d->flagCreator )
        d->flagCreator = new FlagCreator( this, unknown );
    return false;
}


/*! Splits the argument flags into system and user-defined flags. */

void Store::splitSystemExtra()
{
    StringList::Iterator it = d->flagNames.first();
    while ( it ) {
        String n = it->lower();
        if ( n[0] != '\\' )
            d->extra.append( Flag::find( *it ) );
        else if ( n == "\\answered" )
            d->modifyAnsweredFlag = true;
        else if ( n == "\\flagged" )
            d->modifyFlaggedFlag = true;
        else if ( n == "\\deleted" )
            d->modifyDeletedFlag = true;
        else if ( n == "\\seen" )
            d->modifySeenFlag = true;
        else if ( n == "\\draft" )
            d->modifyDraftFlag = true;
        ++it;
    }
    if ( d->modifyAnsweredFlag || d->modifyFlaggedFlag ||
         d->modifyFlaggedFlag || d->modifyDeletedFlag ||
         d->modifyDraftFlag )
        d->system = true;
}


static void addToList( StringList & f, const String & n,
                       bool m, StoreData::Op op )
{
    if ( m && ( op == StoreData::Add || op == StoreData::Replace ) )
        f.append( n + "=1" );
    else if ( ( op == StoreData::Remove && m ) ||
              ( op == StoreData::Replace && !m ) )
        f.append( n + "=0" );
}


static PreparedStatement * prepared[96];

/*! Sends update statements to update the six system flags. */

void Store::updateSystemFlags()
{

    StringList f;
    addToList( f, "answered", d->modifyAnsweredFlag, d->op );
    addToList( f, "flagged", d->modifyFlaggedFlag, d->op );
    addToList( f, "deleted", d->modifyDeletedFlag, d->op );
    addToList( f, "seen", d->modifySeenFlag, d->op );
    addToList( f, "draft", d->modifyDraftFlag, d->op );
    Query * q;
    if ( d->s.isRange() ) {
        uint n = 0;
        if ( d->modifyDraftFlag )
            n += 1;
        if ( d->modifySeenFlag )
            n += 2;
        if ( d->modifyDeletedFlag )
            n += 4;
        if ( d->modifyFlaggedFlag )
            n += 8;
        if ( d->modifyAnsweredFlag )
            n += 16;
        if ( d->op == StoreData::Remove )
            n += 32;
        if ( d->op == StoreData::Replace )
            n += 64;
        if ( !prepared[n] )
            prepared[n] = new PreparedStatement( "update messages "
                                                 "set " + f.join("," ) +
                                                 "where "
                                                 "mailbox=$1 and "
                                                 "uid>=$2 and uid<=$3" );
        q = new Query( *prepared[n], this );
        q->bind( 1, imap()->session()->mailbox()->id() );
        q->bind( 2, d->s.smallest() );
        q->bind( 2, d->s.largest() );
    }
    else {
    q = new Query( "update messages set " + f.join( "," ) +
                   " where " + d->s.where(), this );
    }
    d->transaction->enqueue( q );
}


/*! Issues database commands to kill any rows we may not want at the
    end. At the moment this is a little too harsh - some rows are
    killed by this function and reinserted by addExtraFlags() a moment
    later. Is that a problem? Only time and profiling will show.
*/

void Store::killSuperfluousRows()
{
    Query * q;
    if ( d->op == StoreData::Remove && !d->extra.isEmpty() ) {
        StringList cond;
        List<Flag>::Iterator it( d->extra.first() );
        while ( it ) {
            cond.append( "flag=" + fn( it->id() ) );
            ++it;
        }
        q = new Query( "delete from extra_flags where " + d->s.where() +
                       " and (" + cond.join( " or " ) + ")", this);
    }
    else if ( d->op == StoreData::Replace ) {
        // this is the too-harsh bit. very harsh.
        q = new Query( "delete from extra_flags where " + d->s.where(),
                       this);
    }
    d->transaction->enqueue( q );

}


/*! Adds rows for all flags that should be there/should be added. See
    killSuperfluousRows().
*/

void Store::addExtraFlags()
{
    if ( d->op != StoreData::Remove )
        return;
    if ( d->extra.isEmpty() )
        return;

    Mailbox * m = imap()->session()->mailbox();
    uint msn = d->s.count();
    while ( msn > 0 ) {
        msn--;
        uint uid = d->s.value( msn );
        List<Flag>::Iterator it( d->extra.first() );
        Query * q;
        while ( it ) {
            q = new Query( "insert into extra_flags "
                           "(mailbox,uid,flag) values ($1,$2,$3)",
                           this );
            q->bind( 1, m->id() );
            q->bind( 2, uid );
            q->bind( 3, it->id() );
            d->transaction->enqueue( q );
            ++it;
        }
    }
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
    uint i = 0;
    ImapSession * s = imap()->session();
    while ( i < max ) {
        uint uid = d->s.value( i );
        uint msn = s->msn( uid );
        i++;
        respond( fn( msn ) + " FETCH (UID " +
                 fn( uid ) + " FLAGS (" +
                 d->flagNames.join( " " ) + "))" );
    }
}


/*! Sends a command to the database to get all the flags for the
    messages we just touched. This makes sure to get them in order of
    UID. dumpFetchResponses() depends on that.
*/

void Store::sendFetches()
{
    d->fetchSystem
        = new Query( "select uid, seen, draft, flagged, answered, deleted "
                     "from messages where mailbox=$1 and " + d->s.where() +
                     " order by uid",
                     this );
    d->fetchExtra
        = new Query( "select flag, uid from extra_flags "
                     "where mailbox=$1 and " + d->s.where() +
                     " order by uid",
                     this );
    d->fetchSystem->bind( 1, imap()->session()->mailbox()->id() );
    d->fetchExtra->bind( 1, imap()->session()->mailbox()->id() );
    d->fetchSystem->execute();
    d->fetchExtra->execute();
}


/*! Dumps all the flags for all the relevant messages, as fetched from
    the database. Does not update any cached Message objects for lack
    of an API. Later.

    Returns true if it did all its work and false if there's more to do.
*/

bool Store::dumpFetchResponses()
{
    if ( !d->fetchExtra->done() || !d->fetchSystem->done() )
        return false;

    Row * extra = d->fetchExtra->nextRow();
    uint extraUid = 0;
    if ( extra )
        extraUid = extra->getInt( "uid" );
    Row * system = 0;
    ImapSession * s = imap()->session();
    while ( (system=d->fetchSystem->nextRow()) != 0 ) {
        uint uid = system->getInt( "uid" );
        StringList r;
        if ( system->getBoolean( "answered" ) )
            r.append( "\\answered" );
        if ( system->getBoolean( "deleted" ) )
            r.append( "\\deleted" );
        if ( system->getBoolean( "draft" ) )
            r.append( "\\draft" );
        if ( system->getBoolean( "flagged" ) )
            r.append( "\\flagged" );
        if ( s->isRecent( uid ) )
            r.append( "\\recent" );
        if ( system->getBoolean( "seen" ) )
            r.append( "\\seen" );
        while ( extra && extraUid == uid ) {
            Flag * f = Flag::find( extra->getInt( "flag" ) );
            if ( f )
                r.append( f->name() );
            extra = d->fetchExtra->nextRow();
            extraUid = extra->getInt( "uid" );
        }
        uint msn = s->msn( uid );
        respond( fn( msn ) + " FETCH (UID " +
                 fn( uid ) + " FLAGS (" +
                 r.join( " " ) + "))" );
    }
    return true;
}
