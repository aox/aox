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
        : readOnly( false ), annotate( false ),
          usedFlags( 0 ),
          mailbox( 0 ), session( 0 ), permissions( 0 )
    {}

    String name;
    bool readOnly;
    bool annotate;
    Query * usedFlags;
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
    d->name = astring();
    if ( present( " (" ) ) {
        bool more = true;
        while ( ok() && more ) {
            // select-param can be a list or an astring. in our case,
            // only astring is legal, since we advertise no extension
            // that permits the list.
            String param = astring().lower();
            if ( param == "annotate" )
                d->annotate = true;
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
    if ( !d->mailbox ) {
        d->mailbox = Mailbox::find( imap()->mailboxName( d->name ) );
        if ( !d->mailbox )
            error( No, d->name + " does not exist" );
        else if ( d->mailbox->synthetic() )
            error( No, d->name + " is not in the database" );
        else if ( d->mailbox->deleted() )
            error( No, d->name + " is deleted" );

        if ( !ok() ) {
            finish();
            return;
        }
    }

    if ( !d->permissions ) {
        d->permissions = new Permissions( d->mailbox, imap()->user(),
                                          this );
    }
    if ( d->permissions && !d->session ) {
        if ( !d->permissions->ready() )
            return;
        if ( !d->permissions->allowed( Permissions::Read ) ) {
            error( No, d->name + " is not accessible" );
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
        d->session->setAnnotateUpdates( d->annotate );
        d->session->refresh( this );
    }

    if ( !d->usedFlags ) {
        d->usedFlags = new Query( "select distinct flag from flags where "
                                  "mailbox=$1 "
                                  "order by flag",
                                  this );
        d->usedFlags->bind( 1, d->mailbox->id() );
        d->usedFlags->execute();
    }

    if ( !d->usedFlags->done() )
        return;

    if ( !d->session->initialised() )
        return;
    d->session->clearExpunged();

    String flags = "\\Deleted \\Answered \\Flagged \\Draft \\Seen";
    if ( d->usedFlags->hasResults() ) {
        Row * r = 0;
        while ( (r=d->usedFlags->nextRow()) != 0 ) {
            Flag * f = Flag::find( r->getInt( "flag" ) );
            if ( f && !f->system() ) {
                flags.append( " " );
                flags.append( f->name() );
            }
        }
    }

    respond( "FLAGS (" + flags + ")" );

    respond( fn( d->session->count() ) + " EXISTS" );
    respond( fn( d->session->recent().count() ) + " RECENT" );
    respond( "OK [UNSEEN " +
             fn( d->session->msn( d->session->firstUnseen() ) ) + "]"
             " first unseen" );

    uint n = d->session->uidnext();
    respond( "OK [UIDNEXT " + fn( n ) + "] next uid" );
    d->session->setAnnounced( n );

    respond( "OK [UIDVALIDITY " + fn( d->session->uidvalidity() ) + "]"
             " uid validity" );
    respond( "OK [PERMANENTFLAGS (" + flags +" \\*)] permanent flags" );
    if ( d->session->readOnly() )
        respond( "OK [READ-ONLY] done", Tagged );
    else
        respond( "OK [READ-WRITE] done", Tagged );

    imap()->beginSession( d->session );
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
