// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "select.h"

#include "imap.h"
#include "flag.h"
#include "user.h"
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
          usedFlags( 0 ), highestModseq( 0 ),
          mailbox( 0 ), session( 0 ), permissions( 0 )
    {}

    bool readOnly;
    bool annotate;
    bool condstore;
    Query * usedFlags;
    Query * highestModseq;
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
        d->session->refresh( this );
    }

    if ( !d->usedFlags && d->mailbox->uidnext() > 1 ) {
        d->usedFlags = new Query( "select distinct flag from flags where "
                                  "mailbox=$1 "
                                  "order by flag",
                                  this );
        d->usedFlags->bind( 1, d->mailbox->id() );
        d->usedFlags->execute();
    }

    if ( !d->highestModseq && imap()->clientSupports( IMAP::Condstore ) ) {
        d->highestModseq = new Query( "select coalesce(max(modseq),1) "
                                      "as hms from mailbox_messages "
                                      "where mailbox=$1",
                                      this );
        d->highestModseq->bind( 1, d->mailbox->id() );
        d->highestModseq->execute();
    }

    if ( d->usedFlags && !d->usedFlags->done() )
        return;

    if ( d->highestModseq && !d->highestModseq->done() )
        return;

    if ( !d->session->initialised() )
        return;

    d->session->clearExpunged();
    ((Session*)d->session)->emitResponses( Session::New );

    respond( "OK [UIDVALIDITY " + fn( d->session->uidvalidity() ) + "]"
             " uid validity" );

    uint unseen = d->session->msn( d->session->firstUnseen() );
    if ( unseen != 0 )
        respond( "OK [UNSEEN " + fn( unseen ) + "] first unseen" );

    if ( d->highestModseq ) {
        Row * r = d->highestModseq->nextRow();
        int64 hms = 1;
        if ( r )
            hms = r->getBigint( "hms" );
        respond( "OK [HIGHESTMODSEQ " + fn( hms ) + "] highest modseq" );
    }

    List<Flag> flags;
    Flag * f = 0;
    f = Flag::find( "\\Deleted" );
    if ( f )
        flags.append( f );
    f = Flag::find( "\\Answered" );
    if ( f )
        flags.append( f );
    f = Flag::find( "\\Flagged" );
    if ( f )
        flags.append( f );
    f = Flag::find( "\\Draft" );
    if ( f )
        flags.append( f );
    f = Flag::find( "\\Seen" );
    if ( f )
        flags.append( f );

    if ( d->usedFlags && d->usedFlags->hasResults() ) {
        Row * r = 0;
        while ( (r=d->usedFlags->nextRow()) != 0 ) {
            Flag * f = Flag::find( r->getInt( "flag" ) );
            if ( f )
                flags.append( f );
        }
    }

    d->session->addFlags( &flags, this );

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
