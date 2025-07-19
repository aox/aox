// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "select.h"

#include "map.h"
#include "imap.h"
#include "flag.h"
#include "user.h"
#include "cache.h"
#include "fetch.h"
#include "timer.h"
#include "query.h"
#include "message.h"
#include "mailbox.h"
#include "imapsession.h"
#include "permissions.h"
#include "transaction.h"
#include "mailboxgroup.h"


class SelectData
    : public Garbage
{
public:
    SelectData()
        : readOnly( false ), annotate( false ), condstore( false ),
          needFirstUnseen( false ), unicode( false ), qresync( false ),
          firstUnseen( 0 ), allFlags( 0 ), updated( 0 ),
          mailbox( 0 ), session( 0 ), permissions( 0 ),
          cacheFirstUnseen( 0 ),
          lastUidValidity( 0 ), lastModSeq( 0 ), firstFetch( 0 )
    {}

    bool readOnly;
    bool annotate;
    bool condstore;
    bool needFirstUnseen;
    bool unicode;
    bool qresync;
    Query * firstUnseen;
    Query * allFlags;
    Query * updated;
    Mailbox * mailbox;
    ImapSession * session;
    Permissions * permissions;
    Query * cacheFirstUnseen;
    uint lastUidValidity;
    uint lastModSeq;
    IntegerSet knownUids;
    Fetch * firstFetch;

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
            else if ( param == "utf8" )
                d->unicode = true;
            else if ( param == "qresync" )
                parseQResyncParams();
            else
                error( Bad, "Unknown select-param: " + param );
            more = present( " " );
        }
        require( ")" );
    }
    end();
}


/*! This parses the RFC5162 additional Select parameters. If this
    seems overly complex, that's because the RFC is just that.
*/

void Select::parseQResyncParams()
{
    d->qresync = true;
    space();
    require( "(" ); // alexey loves parens
    d->lastUidValidity = number();
    space();
    d->lastModSeq = number();
    if ( nextChar() == ' ' ) {
        space();
        if(nextChar() >= '1' && nextChar() <= '9') {
            d->knownUids = set( false );
            if ( nextChar() == ' ' )
                space();
        }
        if ( nextChar() == '(' ) {
            require( "(" ); // alexey loves parens
            // we ignore the MSNs: clients that cache a lot don't use
            // MSNs much anyway.
            set( false );
            space();
            set( false );
            require( ")" );
        }
    }
    require( ")" );
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
        if ( d->qresync )
            imap()->setClientSupports( IMAP::QResync );
        if ( d->condstore )
            imap()->setClientSupports( IMAP::Condstore );
        if ( d->annotate )
            imap()->setClientSupports( IMAP::Annotate );
        if ( d->mailbox->deleted() )
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

    if ( d->lastModSeq < 1 )
        d->lastModSeq = d->mailbox->nextModSeq() - 1;

    if ( !transaction() )
        setTransaction( new Transaction( this ) );

    if ( !::firstUnseenCache )
        ::firstUnseenCache = new SelectData::FirstUnseenCache;

    if ( !d->session ) {
        d->session = new ImapSession( imap(), d->mailbox,
                                      d->readOnly, d->unicode,
                                      d->mailbox->nextModSeq() );
        d->session->setPermissions( d->permissions );
        imap()->setSession( d->session );
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

    if ( d->lastModSeq < d->mailbox->nextModSeq() - 1 && !d->updated ) {
        if ( d->knownUids.isEmpty() ) {
            d->updated = new Query( "select uid from deleted_messages "
                                    "where mailbox=$1 and modseq > $2"
                                    " union "
                                    "select uid from mailbox_messages "
                                    "where mailbox=$1 and modseq > $2",
                                    this );
        }
        else {
            d->updated = new Query( "select uid from deleted_messages "
                                    "where mailbox=$1 and modseq > $2 "
                                    "and uid=any($3)"
                                    " union "
                                    "select uid from mailbox_messages "
                                    "where mailbox=$1 and modseq > $2 "
                                    "and uid=any($3)",
                                    this );
            d->updated->bind( 3, d->knownUids );
        }
        d->updated->bind( 1, d->mailbox->id() );
        d->updated->bind( 2, d->lastModSeq );
        transaction()->enqueue( d->updated );
    }

    if ( d->needFirstUnseen && !d->firstUnseen ) {
        d->firstUnseen
            = new Query( "select uid from mailbox_messages mm "
                         "where mailbox=$1 and not seen "
                         "order by uid limit 1", this );
        d->firstUnseen->bind( 1, d->mailbox->id() );
        transaction()->enqueue( d->firstUnseen );
    }

    transaction()->execute();

    if ( ( d->updated && !d->updated->done() ) ||
         ( d->firstUnseen && !d->firstUnseen->done() ) )
        return;

    if ( d->updated && !d->firstFetch ) {
        IntegerSet s;
        while ( d->updated->hasResults() ) {
            Row * r = d->updated->nextRow();
            s.add( r->getInt( "uid" ) );
        }
        if ( !s.isEmpty() ) {
            d->firstFetch = new Fetch( true, false, true,
                                       s, d->lastModSeq, imap(),
                                       transaction() );
            d->firstFetch->setState( Command::Executing );
            d->session->emitUpdates( transaction() );
        }
    }
    if ( d->firstFetch &&
         d->firstFetch->state() != Finished &&
         d->firstFetch->state() != Retired )
        return;

    // emitUpdates often calls Imap::runCommands, which calls this
    // function, which will then change its state to Finished. so
    // check that and don't repeat the last few responses.
    d->session->emitUpdates( transaction() );
    if ( state() != Executing )
        return;

    transaction()->commit();
    if ( transaction()->state() == Transaction::Executing )
        return;

    respond( "OK [UIDVALIDITY " + fn( d->session->uidvalidity() ) + "]"
             " uid validity" );

    respond( "OK [MAILBOXID (f" + fn( d->mailbox->id() ) + ")]"
             " stable mailbox ID" );

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
