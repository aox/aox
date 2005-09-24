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
          transaction( 0 ), flagCreator( 0 ), annotationCreator( 0 )
    {}
    MessageSet s;
    StringList flagNames;

    enum Op { AddFlags, ReplaceFlags, RemoveFlags, ReplaceAnnotations } op;

    bool silent;
    bool uid;
    bool checkedPermission;

    bool fetching;

    Transaction * transaction;
    List<Flag> flags;
    FlagCreator * flagCreator;
    AnnotationCreator * annotationCreator;

    struct Annotation
        : public Garbage
    {
        Annotation(): annotation( 0 ), shared( false ) {}
        String name;
        String value;
        String contentType;
        String contentLanguage;
        String displayName;
        ::Annotation * annotation;
        bool shared;
    };

    List<Annotation> annotations;
};


/*! \class Store store.h
    Alters message flags (RFC 3501 section 6.4.6).

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
    setGroup( 3 );
}


void Store::parse()
{
    space();
    d->s = set( !d->uid );
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
}




/*! Parses and stores a single annotation entry for later
    processing. Leaves the cursor on the following character
    (space/paren).
*/

void Store::parseAnnotationEntry()
{
    String entry = string();
    if ( entry.startsWith( "/flags/" ) )
        error( Bad, "Cannot set top-level flags using STORE ANNOTATION" );
    if ( entry.find( "//" ) >= 0 )
        error( Bad, "Annotation entry names cannot contain //" );
    if ( entry.endsWith( "/" ) )
        error( Bad, "Annotation entry names cannot end with /" );
    space();
    require( "(" );
    bool more = true;
    while ( more ) {
        String attrib = string();
        if ( attrib.find( ".." ) >= 0 )
            error( Bad, "Consecutive dots not allowed in attribute names" );
        else if ( attrib.startsWith( "vendor." ) )
            error( No, "Vendor extensions not supported; "
                   "contact info@oryx.com" );
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
        List<StoreData::Annotation>::Iterator it( d->annotations );
        while ( it && ( it->name != entry || it->shared != shared ) )
            ++it;
        StoreData::Annotation * a = it;
        if ( !it ) {
            a = new StoreData::Annotation;
            a->name = entry;
            d->annotations.append( a );
            a->shared = shared;
        }
        if ( attrib == "value" )
            a->value = value;
        else if ( attrib == "content-type" )
            a->contentType = value;
        else if ( attrib == "content-language" )
            a->contentLanguage = value;
        else if ( attrib == "display-name" )
            a->displayName = value;
        else
            error( Bad, "Unknown attribute: " + attrib );

        more = present( " " );
    }
    require( ")" );
}



/*! Stores all the annotations/flags, using potentially enormous
    numbers if database queries. The command is kept atomic by the use
    of a Transaction.
*/

void Store::execute()
{
    if ( d->s.isEmpty() ) {
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
            List<StoreData::Annotation>::Iterator it( d->annotations );
            while ( it ) {
                if ( it->shared )
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
    List<StoreData::Annotation>::Iterator it( d->annotations );
    StringList unknown;
    while ( it ) {
        if ( !it->annotation )
            it->annotation = Annotation::find( it->name );
        if ( !it->annotation )
            unknown.append( it->name );
        ++it;
    }
    if ( unknown.isEmpty() )
        return true;
    if ( !d->flagCreator )
        d->annotationCreator = new AnnotationCreator( this, unknown );
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
    List<StoreData::Annotation>::Iterator it( d->annotations );
    String w = d->s.where();
    Mailbox * m = imap()->session()->mailbox();
    User * u = imap()->user();
    while ( it ) {
        Query * q;
        String o = "owner=$3";
        if ( it->shared )
            o = "owner is null";
        if ( it->value.isEmpty() ) {
            q = new Query( "delete from annotations where "
                                   "mailbox=$1 and (" + w + ") and "
                                   "name=$2 and " + o, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, it->annotation->id() );
            q->bind( 3, u->id() );
            d->transaction->enqueue( q );
        }
        else {
            String existing = "where mailbox=$1 and (" + w + ") and name=$2 "
                              "and " + o;
            q = new Query( "update annotations set "
                           "value=$4, type=$5, language=$6, displayname=$7 " +
                           existing, 0 );
            q->bind( 1, m->id() );
            q->bind( 2, it->annotation->id() );
            q->bind( 3, u->id() );
            bind( q, 4, it->value );
            bind( q, 5, it->contentType );
            bind( q, 6, it->contentLanguage );
            bind( q, 7, it->displayName );
            d->transaction->enqueue( q );

            q = new Query( "insert into annotations "
                           "(mailbox, uid, owner, name, value, type, "
                           " language, displayname) "
                           "select $1,uid,$3,$2,$4,$5,$6,$7 "
                           "from messages where "
                           "mailbox=$1 and (" + w + ") and uid not in "
                           "(select uid from annotations " + existing + ")",
                           0 );
            q->bind( 1, m->id() );
            q->bind( 2, it->annotation->id() );
            q->bind( 3, u->id() );
            bind( q, 4, it->value );
            bind( q, 5, it->contentType );
            bind( q, 6, it->contentLanguage );
            bind( q, 7, it->displayName );
            d->transaction->enqueue( q );
        }
        ++it;
    }
}
