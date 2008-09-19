// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "handlers/fetch.h"
#include "command.h"
#include "fetcher.h"
#include "mailbox.h"
#include "message.h"
#include "scope.h"
#include "imap.h"
#include "flag.h"


class ImapSessionData
    : public Garbage
{
public:
    ImapSessionData(): i( 0 ), l( 0 ),
                       exists( 0 ), recent( 0 ),
                       uidnext( 0 ), nms( 0 ), cms( 0 ),
                       emitting( false ) {}
    class IMAP * i;
    Log * l;
    MessageSet expungedFetched;
    MessageSet changed;
    uint exists;
    uint recent;
    uint uidnext;
    int64 nms;
    int64 cms;
    StringList flags;
    List<int64> ignorable;
    bool emitting;
};


/*! \class ImapSession imapsession.h
    This class inherits from the Session class, and provides two
    IMAP-specific output functions.
*/

/*! Creates a new ImapSession for the Mailbox \a m to be accessed
    using \a imap. If \a readOnly is true, the session is read-only.
*/

ImapSession::ImapSession( IMAP * imap, Mailbox *m, bool readOnly )
    : Session( m, readOnly ),
      d( new ImapSessionData )
{
    d->i = imap;
    Scope x( imap->log() );
    d->l = new Log( Log::IMAP );
}


ImapSession::~ImapSession()
{
}


/*! Returns a pointer to the IMAP connection that's using this session. */

IMAP * ImapSession::imap() const
{
    return d->i;
}


/*! Emits whatever responses we can to the IMAP client. */

void ImapSession::emitUpdates()
{
    if ( d->emitting )
        return;
    d->emitting = true;

    Scope x( d->l );

    MessageSet e;
    e.add( expunged() );
    while ( !e.isEmpty() ) {
        (void)new ImapExpungeResponse( e.smallest(), this );
        e.remove( e.smallest() );
    }

    emitFlagUpdates();
    clearUnannounced();

    if ( d->uidnext < uidnext() ) {
        uint x = messages().count();
        if ( x > d->exists || !d->uidnext ) {
            d->exists = x;
            (void)new ImapResponse( this, fn( x ) + " EXISTS" );
        }

        uint r = recent().count();
        if ( d->recent != r || !d->uidnext ) {
            d->recent = r;
            (void)new ImapResponse( this, fn( r ) + " RECENT" );
        }
        
        d->uidnext = uidnext();
        (void)new ImapResponse( this,
                                "OK [UIDNEXT " + fn( d->uidnext ) +
                                "] next uid" );
    }

    if ( d->nms < nextModSeq() )
        d->nms = nextModSeq();
    if ( d->changed.isEmpty() )
        d->cms = d->nms;

    d->i->unblockCommands();

    d->emitting = false;
}


/*! This private helper starts/sends whatever flag updates are needed.
*/

void ImapSession::emitFlagUpdates()
{
    if ( !d->nms )
        return;
    if ( d->cms >= nextModSeq() )
        return;

    d->changed.add( unannounced().intersection( messages() ) );

    if ( d->changed.isEmpty() )
        return;

    List<Command>::Iterator c( d->i->commands() );
    if ( !c || c->state() != Command::Executing )
        return;

    while ( !d->ignorable.isEmpty() ) {
        List<int64>::Iterator i( d->ignorable );
        bool f = false;
        while ( i ) {
            if ( d->cms > *i ) {
                d->ignorable.take( i );
            }
            else if ( d->cms == *i ) {
                log( "Not sending flag updates about modseq " + fn( d->cms ),
                     Log::Debug );
                d->ignorable.take( i );
                f = true;
            }
            else {
                ++i;
            }
        }
        if ( f )
            d->cms++;
        else
            d->ignorable.clear();
    }

    (void)new Fetch( true, d->i->clientSupports( IMAP::Annotate ),
                     d->changed, d->cms - 1, d->i );
    d->changed.clear();
}


/*! Records that \a set was fetched while also expunged. If any
    messages in \a set have already been recorded,
    recordExpungedFetch() summarily closes the IMAP connection.
*/

void ImapSession::recordExpungedFetch( const MessageSet & set )
{
    MessageSet already = set.intersection( d->expungedFetched );
    d->expungedFetched.add( set );
    if ( already.isEmpty() )
        return;

    (void)new ImapByeResponse( d->i,
                               "[CLIENTBUG] "
                               "These messages have been expunged: " +
                               set.set() );
}


/*! Records that no flag/annotation/modseq update is to be sent for \a
    ms. ImapSession may send one anyway, but tries to avoid it.
*/

void ImapSession::ignoreModSeq( int64 ms )
{
    d->ignorable.append( new int64( ms ) );
}


/*! \class ImapExpungeResponse imapsession.h

    The ImapExpungeResponse the expun an Expunge response. It can
    formulate the right text and modify the session to account for the
    response's having been sent.
*/


/*! Constructs an ImapExpungeResponse for \a uid in \a session.

*/

ImapExpungeResponse::ImapExpungeResponse( uint uid, ImapSession * session )
    : ImapResponse( session ), u( uid )
{
    setChangesMsn();
}


String ImapExpungeResponse::text() const
{
    String r;
    uint msn = session()->msn( u );
    if ( !msn ) {
        log( "Warning: No MSN for UID " + fn( u ), Log::Error );
        return r; // can this happen? no?
    }

    r.append( fn( msn ) );
    r.append( " EXPUNGE" );
    return r;
}


void ImapExpungeResponse::setSent()
{
    session()->clearExpunged( u );
    ImapResponse::setSent();
}
