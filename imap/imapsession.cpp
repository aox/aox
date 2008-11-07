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
                       emitting( false ),
                       existsResponse( 0 ), recentResponse( 0 ),
                       uidnextResponse( 0 ) {}

    class IMAP * i;
    Log * l;
    MessageSet expungesReported;
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

    class ExistsResponse
        : public ImapResponse
    {
    public:
        ExistsResponse( ImapSession * s, ImapSessionData * data )
            : ImapResponse( s ), d( data ) {
        }
        String text() const {
            session()->clearUnannounced();
            uint x = session()->messages().count();
            if ( x == d->exists && d->uidnext )
                return "";
            d->exists = x;
            return fn( x ) + " EXISTS";
        }
        void setSent() {
            d->existsResponse = 0;
            ImapResponse::setSent();
        }

        ImapSessionData * d;
    };

    class RecentResponse
        : public ImapResponse
    {
    public:
        RecentResponse( ImapSession * s, ImapSessionData * data )
            : ImapResponse( s ), d( data ) {
        }
        String text() const {
            uint x = session()->recent().count();
            if ( x == d->recent && d->uidnext )
                return "";
            d->recent = x;
            return fn( x ) + " RECENT";
        }
        void setSent() {
            d->recentResponse = 0;
            ImapResponse::setSent();
        }

        ImapSessionData * d;
    };

    class UidnextResponse
        : public ImapResponse
    {
    public:
        UidnextResponse( ImapSession * s, ImapSessionData * data )
            : ImapResponse( s ), d( data ) {
        }
        String text() const {
            uint x = session()->uidnext();
            if ( x <= d->uidnext )
                return "";
            d->uidnext = x;
            return "OK [" + fn( x ) + " UIDNEXT] next uid";
        }
        void setSent() {
            d->uidnextResponse = 0;
            ImapResponse::setSent();
        }

        ImapSessionData * d;
    };

    ExistsResponse * existsResponse;
    RecentResponse * recentResponse;
    UidnextResponse * uidnextResponse;
};


/*! \class ImapSession imapsession.h
    This class inherits from the Session class, and provides two
    IMAP-specific output functions.
*/

/*! Creates a new ImapSession for the Mailbox \a m to be accessed
    using \a imap. If \a readOnly is true, the session is read-only.
*/

ImapSession::ImapSession( IMAP * imap, Mailbox * m, bool readOnly )
    : Session( m, imap, readOnly ),
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


/*! Emits whatever responses we can to the IMAP client, using \a t for
    the database work.
*/

void ImapSession::emitUpdates( Transaction * t )
{
    if ( d->emitting )
        return;
    d->emitting = true;
    bool work = false;

    Scope x( d->l );

    MessageSet e;
    e.add( expunged() );
    if ( !e.isEmpty() ) {
        d->expungesReported = d->expungesReported.intersection( e );
        e.remove( d->expungesReported );
        while ( !e.isEmpty() ) {
            (void)new ImapExpungeResponse( e.smallest(), this );
            work = true;
            e.remove( e.smallest() );
        }
    }

    emitFlagUpdates( t );

    if ( d->uidnext < uidnext() ) {
        if ( !d->existsResponse ) {
            d->existsResponse =
                new ImapSessionData::ExistsResponse( this, d );
            work = true;
        }
        if ( !d->recentResponse ) {
            d->recentResponse =
                new ImapSessionData::RecentResponse( this, d );
            work = true;
        }
        if ( !d->uidnextResponse ) {
            d->uidnextResponse =
                new ImapSessionData::UidnextResponse( this, d );
            work = true;
        }
    }

    if ( d->nms < nextModSeq() )
        d->nms = nextModSeq();
    if ( d->changed.isEmpty() )
        d->cms = d->nms;

    if ( work )
        d->i->unblockCommands();
    d->i->emitResponses();

    d->emitting = false;
}


/*! This private helper starts/sends whatever flag updates are needed,
    using \a t for the database work.
*/

void ImapSession::emitFlagUpdates( Transaction * t )
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
                     d->changed, d->cms - 1, d->i, t );
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
                               "BYE [CLIENTBUG] "
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


/*! This reimplementation ensures that the ImapSession doesn't think
    the EXISTS number is higher than what the IMAP client thinks.

    This reimplementation doesn't use \a u, only Session does.
*/

void ImapSession::clearExpunged( uint u )
{
    Session::clearExpunged( u );
    if ( d->exists )
        d->exists--;
}


/*! This reimplementation sends a BYE response and lets it be
    processed in the usual manner.
*/

void ImapSession::abort()
{
    if ( d->i && d->i->session() == this )
        (void)new ImapByeResponse( d->i, "BYE Session must be aborted" );
}
