// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "select.h"

#include "imap.h"
#include "flag.h"
#include "user.h"
#include "timer.h"
#include "query.h"
#include "message.h"
#include "mailbox.h"
#include "messageset.h"
#include "imapsession.h"
#include "permissions.h"


class SelectData
    : public Garbage
{
public:
    SelectData()
        : readOnly( false ), annotate( false ), condstore( false ),
          firstUnseen( 0 ),
          mailbox( 0 ), session( 0 ), permissions( 0 )
    {}

    bool readOnly;
    bool annotate;
    bool condstore;
    Query * firstUnseen;
    Mailbox * mailbox;
    ImapSession * session;
    Permissions * permissions;
};


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
            String param = astring().lower();
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
        if ( imap()->session() ) {
            respond( "OK [CLOSED] " );
            imap()->endSession();
        }
        d->session = new ImapSession( imap(), d->mailbox, d->readOnly );
        d->session->setPermissions( d->permissions );
        imap()->beginSession( d->session );
    }

    if ( !d->session->initialised() )
        return;

    d->session->emitUpdates();
    // emitUpdates often calls Imap::runCommands, which calls this
    // function, which will then change its state to Finished. so
    // check that and don't repeat the last few responses.
    if ( state() != Executing )
        return;
    
    if ( !d->firstUnseen && !d->session->isEmpty() ) {
        uint seen = Flag::id( "\\seen" );
        String sq;
        if ( seen )
            sq = " and flag=" + fn( seen );
        else
            sq = " and flag in "
                 "(select id from flags where lower(name)='\\seen')";
        d->firstUnseen
            = new Query( "select uid from mailbox_messages mm "
                         "where mailbox=$1 and uid not in "
                         "(select uid from flags where mailbox=$1 " + sq + ") "
                         "order by mm.uid limit 1", this );
        d->firstUnseen->bind( 1, d->mailbox->id() );
        d->firstUnseen->execute();
    }

    if ( d->firstUnseen && !d->firstUnseen->done() )
        return;

    respond( "OK [UIDVALIDITY " + fn( d->session->uidvalidity() ) + "]"
             " uid validity" );

    if ( d->firstUnseen ) {
        Row * r = d->firstUnseen->nextRow();
        uint unseen = 0;
        if ( r )
            unseen = r->getInt( "uid" );
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

    String fl = Flag::allFlags().join( " " );
    respond( "FLAGS (" + fl + ")" );
    respond( "OK [PERMANENTFLAGS (" + fl + " \\*)] permanent flags" );

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
