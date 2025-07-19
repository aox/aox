// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "imapsession.h"

#include "helperrowcreator.h"
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
                       emitting( false ), unicode( false ),
                       existsResponse( 0 ), recentResponse( 0 ),
                       uidnextResponse( 0 ), highestModseqResponse( 0 ),
                       flagUpdate( 0 ), permaFlagUpdate( 0 ) {}

    class IMAP * i;
    Log * l;
    IntegerSet expungesReported;
    IntegerSet expungedFetched;
    uint exists;
    uint recent;
    uint uidnext;
    int64 nms;
    int64 cms;
    EStringList flags;
    List<int64> ignorable;
    bool emitting;
    bool unicode;

    class ExistsResponse
        : public ImapResponse
    {
    public:
        ExistsResponse( ImapSession * s, ImapSessionData * data )
            : ImapResponse( s ), d( data ) {
        }
        EString text() const {
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
        EString text() const {
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
        EString text() const {
            uint x = session()->uidnext();
            if ( x <= d->uidnext )
                return "";
            d->uidnext = x;
            return "OK [UIDNEXT " + fn( x ) + "] next uid";
        }
        void setSent() {
            d->uidnextResponse = 0;
            ImapResponse::setSent();
        }

        ImapSessionData * d;
    };

    class HighestModseqResponse
        : public ImapResponse
    {
    public:
        HighestModseqResponse( ImapSession * s, ImapSessionData * data )
            : ImapResponse( s ), d( data ) {
        }
        EString text() const {
            uint x = session()->nextModSeq();
            if ( x <= d->nms || x < 2 )
                return "";
            d->nms = x;
            return "OK [HIGHESTMODSEQ " + fn( x - 1 ) + "] next modseq - 1";
        }
        void setSent() {
            d->highestModseqResponse = 0;
            ImapResponse::setSent();
        }

        ImapSessionData * d;
    };

    ExistsResponse * existsResponse;
    RecentResponse * recentResponse;
    UidnextResponse * uidnextResponse;
    HighestModseqResponse * highestModseqResponse;

    uint flagUpdate;
    uint permaFlagUpdate;

    class FlagUpdateResponse
        : public ImapResponse
    {
    public:
        FlagUpdateResponse( ImapSession * s, ImapSessionData * d, bool p,
                            FlagCreator * c )
            : ImapResponse( s ), permahack( p ), creator( c ), limit( 0 ) {
            if ( p )
                limit = &d->permaFlagUpdate;
            else
                limit = &d->flagUpdate;
        }
        EString text() const {
            if ( *limit >= Flag::largestId() &&
                 ( !creator || !creator->inserted() ) )
                return "";
            EString x;
            if ( permahack )
                x.append( "OK [PERMANENT" );
            x.append( "FLAGS (" );
            EStringList all = Flag::allFlags();
            if ( creator )
                all.append( *creator->allFlags() );
            all.removeDuplicates( false );
            x.append( all.sorted()->join( " " ) );
            if ( permahack )
                x.append( " \\*" );
            x.append( ")" );
            if ( permahack )
                x.append( "] permanent flags" );
            return x;
        }
        void setSent() {
            *limit = Flag::largestId();
            if ( creator ) {
                EStringList::Iterator i( creator->allFlags() );
                while ( i ) {
                    uint id = creator->id( *i );
                    if ( id > *limit )
                        *limit = id;
                    ++i;
                }
            }
            ImapResponse::setSent();
        }

        bool permahack;
        FlagCreator * creator;
        uint * limit;
    };
};


/*! \class ImapSession imapsession.h
    This class inherits from the Session class, and provides two
    IMAP-specific output functions.
*/

/*! Creates a new ImapSession for the Mailbox \a m to be accessed
    using \a imap. If \a readOnly is true, the session is read-only.
    If \a unicode is true, the session presents messages in EAI
    format, if false, in classic MIME format. If \a previousModSeq is
    not zero, then the ImapSession will emit flag updates starting at
    that modseq.
*/

ImapSession::ImapSession( IMAP * imap, Mailbox * m, bool readOnly,
                          bool unicode, int64 previousModSeq )
    : Session( m, readOnly ),
      d( new ImapSessionData )
{
    d->i = imap;
    Scope x( imap->log() );
    d->l = new Log;
    d->unicode = unicode;
    d->cms = previousModSeq;
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

    IntegerSet e;
    e.add( expunged() );
    e.remove( d->expungesReported );
    if ( !e.isEmpty() ) {
        d->expungesReported.add( e );
        if ( imap()->clientSupports( IMAP::QResync ) ||
             imap()->clientSupports( IMAP::UidOnly ) ) {
            (void)new ImapVanishedResponse( e, this );
            work = true;
        }
        else {
            while ( !e.isEmpty() ) {
                (void)new ImapExpungeResponse( e.smallest(), this );
                work = true;
                e.remove( e.smallest() );
            }
        }
    }

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

    if ( d->nms < nextModSeq() &&
         !d->highestModseqResponse ) {
        d->highestModseqResponse =
            new ImapSessionData::HighestModseqResponse( this, d );
        work = true;
    }

    emitFlagUpdates( t );

    if ( work )
        d->i->unblockCommands();
    d->i->emitResponses();
    clearUnannounced();

    d->emitting = false;
}


/*! This private helper starts/sends whatever flag updates are needed,
    using \a t for the database work.
*/

void ImapSession::emitFlagUpdates( Transaction * t )
{
    sendFlagUpdate();

    if ( unannounced().isEmpty() )
        return;

    if ( d->cms == 0 ) {
        d->cms = d->nms;
        return;
    }

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

    Fetch * f = new Fetch( true, d->i->clientSupports( IMAP::Annotate ), false,
                           unannounced().intersection( messages() ),
                           d->cms - 1, d->i, t );
    d->cms = d->nms;
    f->setState( Command::Executing );
}



/*! Records that \a set was fetched while also expunged. If any
    messages in \a set have already been recorded,
    recordExpungedFetch() summarily closes the IMAP connection.
*/

void ImapSession::recordExpungedFetch( const IntegerSet & set )
{
    IntegerSet already = set.intersection( d->expungedFetched );
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
    int64 * x = (int64*)Allocator::alloc( sizeof( int64 ), 0 );
    *x = ms;
    d->ignorable.append( x );
}


/*! \class ImapVanishedResponse imapsession.h

    The ImapVanishedResponse provides a single Vanished response. It can
    formulate the right text and modify the session to account for the
    response's having been sent.
*/

/*! Constructs an ImapVanishedResponse for \a uids in \a session. */

ImapVanishedResponse::ImapVanishedResponse( const IntegerSet & uids,
                                            ImapSession * session )
    : ImapResponse( session), s( new IntegerSet( uids ) )
{
    setChangesMsn();
}


EString ImapVanishedResponse::text() const
{
    EString r( "VANISHED " );
    r.append( s->set() );
    return r;
}


void ImapVanishedResponse::setSent()
{
    while ( !s->isEmpty() ) {
        int i = s->smallest();
        session()->clearExpunged( i );
        s->remove( i );
    }
    ImapResponse::setSent();
}


/*! \class ImapExpungeResponse imapsession.h

    The ImapExpungeResponse provides a single Expunge response. It can
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


EString ImapExpungeResponse::text() const
{
    EString r;
    uint msn = session()->msn( u );
    if ( !msn ) {
        log( "Warning: No MSN for UID " + fn( u ), Log::Error );
        return r; // can this happen? no?
    }

    r.appendNumber( msn );
    r.append( " EXPUNGE" );
    return r;
}


void ImapExpungeResponse::setSent()
{
    session()->clearExpunged( u );
    ImapResponse::setSent();
}


/*! This reimplementation ensures that the ImapSession doesn't think
    the EXISTS number is higher than what the IMAP client thinks after
    the message with UID \a u is expunged.
*/

void ImapSession::clearExpunged( uint u )
{
    Session::clearExpunged( u );
    d->expungesReported.remove( u );
    if ( d->exists )
        d->exists--;
}


/*! Sends a FLAG blah, used by Flag whenever the flag list grows. */

void ImapSession::sendFlagUpdate()
{
    if ( d->flagUpdate >= Flag::largestId() )
        return;
    (void)new ImapSessionData::FlagUpdateResponse( this, d, false, 0 );
    (void)new ImapSessionData::FlagUpdateResponse( this, d, true, 0 );
}


/*! Sends a FLAG blah, using Flag and also the FlagCreator \a c. Used
    by STORE to make sure creating a flag sends the response.
*/

void ImapSession::sendFlagUpdate( FlagCreator * c )
{
    (void)new ImapSessionData::FlagUpdateResponse( this, d, false, c );
    (void)new ImapSessionData::FlagUpdateResponse( this, d, true, c );
}


/*! Returns true if the server should return messages in EAI form, and
    false if it should use RFC2047 encoding etc.
*/

bool ImapSession::unicode() const
{
    return d->unicode;
}
