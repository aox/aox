// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "select.h"

#include "map.h"
#include "imap.h"
#include "flag.h"
#include "user.h"
#include "cache.h"
#include "timer.h"
#include "query.h"
#include "message.h"
#include "mailbox.h"
#include "imapsession.h"
#include "permissions.h"


class SelectData
    : public Garbage
{
public:
    SelectData()
        : readOnly( false ), annotate( false ), condstore( false ),
          needFirstUnseen( false ),
          firstUnseen( 0 ), allFlags( 0 ),
          mailbox( 0 ), session( 0 ), permissions( 0 )
    {}

    bool readOnly;
    bool annotate;
    bool condstore;
    bool needFirstUnseen;
    Query * firstUnseen;
    Query * allFlags;
    Mailbox * mailbox;
    ImapSession * session;
    Permissions * permissions;

    class FirstUnseenCache
        : public Cache
    {
    public:
        FirstUnseenCache(): Cache( 10 ) {}

        struct MailboxInfo
            : public Garbage
        {
        public:
            MailboxInfo(): Garbage(), fu( 0 ), ms( 0 ) {}
            uint fu;
            int64 ms;
        };

        Map<MailboxInfo> c;

        int64 find( Mailbox * m, int64 ms ) {
            if ( !m || !m->id() )
                return 0;
            MailboxInfo * mi = c.find( m->id() );
            if ( !mi )
                return 0;
            if ( mi->ms < ms )
                c.remove( m->id() );
            if ( mi->ms != ms )
                return 0;
            return mi->fu;
        }

        void insert( Mailbox * m, int64 ms, uint uid ) {
            if ( !m || !m->id() || !ms )
                return;
            MailboxInfo * mi = c.find( m->id() );
            if ( !mi ) {
                mi = new MailboxInfo();
                c.insert( m->id(), mi );
            }
            if ( mi->ms < ms ) {
                mi->fu = uid;
                mi->ms = ms;
            }
        }

        void clear() {
            c.clear();
        }
    };
};


static SelectData::FirstUnseenCache * firstUnseenCache = 0;


/*! \class Select select.h
    Opens a mailbox for read-write access (RFC 3501 section 6.3.1)

    This class implements both Select and Examine. The constructor has
    to tell execute() what to do by setting the readOnly flag.
*/

/*! Creates a Select object to handle SELECT if \a ro if false, and to
    handle EXAMINE if \a ro is true.
*/

Select::Select( bool ro )
    : d( new SelectData )
{
    d->readOnly = ro;
}


void Select::parse()
{
    space();
    d->mailbox = mailbox();
    if ( present( " (" ) ) {
        bool more = true;
        while ( ok() && more ) {
            // select-param can be a list or an astring. in our case,
            // only astring is legal, since we advertise no extension
            // that permits the list.
            EString param = astring().lower();
            if ( param == "annotate" )
                d->annotate = true;
            else if ( param == "condstore" )
                d->condstore = true;
            else
                error( Bad, "Unknown select-param: " + param );
            more = present( " " );
        }
        require( ")" );
    }
    end();
}


void Select::execute()
{
    if ( state() != Executing )
        return;

    if ( Flag::id( "\\Deleted" ) == 0 ) {
        // should only happen when we flush the entire database during
        // testing, so we don't bother being accurate or fast, but
        // simply try again in a second.
        (void)new Timer( this, 1 );
        return;
    }

    if ( !d->permissions ) {
        if ( d->condstore )
            imap()->setClientSupports( IMAP::Condstore );
        if ( d->annotate )
            imap()->setClientSupports( IMAP::Annotate );
        if ( d->mailbox->synthetic() )
            error( No,
                   d->mailbox->name().ascii() + " is not in the database" );
        else if ( d->mailbox->deleted() )
            error( No, d->mailbox->name().ascii() + " is deleted" );

        if ( !ok() ) {
            finish();
            return;
        }

        d->permissions = new Permissions( d->mailbox, imap()->user(),
                                          this );
    }

    if ( d->permissions && !d->session ) {
        if ( !d->permissions->ready() )
            return;
        if ( !d->permissions->allowed( Permissions::Read ) ) {
            error( No, d->mailbox->name().ascii() + " is not accessible" );
            finish();
            return;
        }
        if ( !d->readOnly &&
             !d->permissions->allowed( Permissions::KeepSeen ) )
            d->readOnly = true;
    }

    if ( !d->session ) {
        if ( imap()->session() )
            imap()->endSession();
        d->session = new ImapSession( imap(), d->mailbox, d->readOnly );
        d->session->setPermissions( d->permissions );
        imap()->beginSession( d->session );
    }

    if ( !d->session->initialised() )
        return;

    if ( d->session->isEmpty() )
        d->needFirstUnseen = false;
    else if ( ::firstUnseenCache &&
              ::firstUnseenCache->find( d->mailbox, d->session->nextModSeq() ) )
        d->needFirstUnseen = false;
    else
        d->needFirstUnseen = true;

    if ( d->needFirstUnseen && !d->firstUnseen ) {
        d->firstUnseen
            = new Query( "select uid from mailbox_messages mm "
                         "where mailbox=$1 and uid not in "
                         "(select uid from flags f"
                         " join flag_names fn on (f.flag=fn.id)"
                         " where f.mailbox=$1 and fn.name=$2) "
                         "order by uid limit 1", this );
        d->firstUnseen->bind( 1, d->mailbox->id() );
        d->firstUnseen->bind( 2, "\\seen" );
        d->firstUnseen->execute();
    }

    if ( d->firstUnseen && !d->firstUnseen->done() )
        return;

    d->session->emitUpdates( 0 );
    // emitUpdates often calls Imap::runCommands, which calls this
    // function, which will then change its state to Finished. so
    // check that and don't repeat the last few responses.
    if ( state() != Executing )
        return;

    respond( "OK [UIDVALIDITY " + fn( d->session->uidvalidity() ) + "]"
             " uid validity" );

    if ( d->firstUnseen ) {
        if ( !::firstUnseenCache )
            ::firstUnseenCache = new SelectData::FirstUnseenCache;
        Row * r = d->firstUnseen->nextRow();
        if ( r )
            ::firstUnseenCache->insert( d->mailbox, d->session->nextModSeq(),
                                        r->getInt( "uid" ) );
    }

    if ( ::firstUnseenCache ) {
        uint unseen = ::firstUnseenCache->find( d->mailbox,
                                                d->session->nextModSeq() );
        if ( unseen )
            respond( "OK [UNSEEN " + fn( d->session->msn( unseen ) ) +
                     "] first unseen" );
    }

    if ( imap()->clientSupports( IMAP::Condstore ) &&
         !d->session->isEmpty() ) {
        uint nms = d->session->nextModSeq();
        if ( nms < 2 )
            nms = 2;
        respond( "OK [HIGHESTMODSEQ " + fn( nms-1 ) + "] highest modseq" );
    }

    if ( imap()->clientSupports( IMAP::Annotate ) ) {
        Permissions * p  = d->session->permissions();
        if ( p && p->allowed( Permissions::WriteSharedAnnotation ) )
            respond( "OK [ANNOTATIONS 262144] Arbitrary limit" );
        else
            respond( "OK [ANNOTATIONS READ-ONLY] Missing 'n' right" );
    }

    if ( d->session->readOnly() )
        setRespTextCode( "READ-ONLY" );
    else
        setRespTextCode( "READ-WRITE" );

    finish();
}


/*! \class Examine select.h
    Opens a mailbox for read-only access (RFC 3501 section 6.3.1)

    This class merely inherits from Select and sets the readOnly flag.
    It has no code of its own.
*/

/*! Constructs an Examine handler, which is the same as a Select
    handler, except that it always is read-only.
*/

Examine::Examine()
    : Select( true )
{
}
