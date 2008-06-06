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
    ImapSessionData(): i( 0 ), l( 0 ), unsolicited( false ),
                       exists( 0 ), recent( 0 ),
                       uidnext( 0 ), nms( 0 ), cms( 0 ),
                       emitting( false ) {}
    class IMAP * i;
    Log * l;
    MessageSet expungedFetched;
    MessageSet changed;
    bool unsolicited;
    uint exists;
    uint recent;
    uint uidnext;
    int64 nms;
    int64 cms;
    List<Flag> flags;
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

    emitExpunges();
    emitFlagUpdates();
    clearUnannounced();
    emitUidnext();
    if ( d->nms < nextModSeq() )
        d->nms = nextModSeq();
    if ( d->changed.isEmpty() )
        d->cms = d->nms;

    List<Command>::Iterator c( d->i->commands() );
    if ( c && c->state() == Command::Finished )
        c->emitResponses();

    d->emitting = false;
}


/*! This private helper sends whatever EXPUNGE responses may be
    sent.
*/

void ImapSession::emitExpunges()
{
    MessageSet e;
    e.add( expunged() );
    if ( e.isEmpty() )
        return;

    List<Command>::Iterator c( d->i->commands() );

    bool can = false;
    bool cannot = false;

    while ( c && !cannot ) {
        // expunges are permitted in idle mode
        if ( c->state() == Command::Executing && c->name() == "idle" )
            can = true;
        // we cannot send an expunge while a command is being
        // executed (not without NOTIFY at least...)
        else if ( c->state() == Command::Executing )
            cannot = true;
        // group 2 contains commands during which we may not send
        // expunge, group 3 contains all commands that change
        // flags.
        else if ( c->group() == 2 || c->group() == 3 )
            cannot = true;
        // if there are MSNs in the pipeline we cannot send
        // expunge. the copy rule is due to RFC 2180 section
        // 4.4.1/2
        else if ( c->usesMsn() && c->name() != "copy" )
            cannot = true;
        // if another command is finished, we can.
        else if ( c->state() == Command::Finished )
            can = true;
        ++c;
    }
    if ( cannot || !can )
        return;

    MessageSet m;
    m.add( messages() );

    d->expungedFetched.remove( e );

    while ( !e.isEmpty() ) {
        uint uid = e.value( 1 );
        uint msn = m.index( uid );
        e.remove( uid );
        m.remove( uid );
        enqueue( "* " + fn( msn ) + " EXPUNGE\r\n" );
        if ( d->exists )
            d->exists--;
    }
    clearExpunged();
}


/*! This private helper sends EXISTS, UIDNEXT and RECENT. */

void ImapSession::emitUidnext()
{
    uint n = uidnext();
    if ( n <= d->uidnext )
        return;

    uint x = messages().count();
    if ( x != d->exists || !d->uidnext )
        enqueue( "* " + fn( x ) + " EXISTS\r\n" );

    if ( d->unsolicited ) {
        List<Command>::Iterator c( d->i->commands() );
        if ( c && c->state() == Command::Finished )
            d->unsolicited = false;
        else
            return;
    }
    d->exists = x;

    uint r = recent().count();
    if ( d->recent != r || !d->uidnext ) {
        d->recent = r;
        enqueue( "* " + fn( r ) + " RECENT\r\n" );
    }

    d->uidnext = n;
    enqueue( "* OK [UIDNEXT " + fn( n ) + "] next uid\r\n" );
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

    enqueue( "* BYE [CLIENTBUG] These messages have been expunged: " +
             set.set() + "\r\n" );
    d->i->setState( IMAP::Logout );
}


/*! Sends \a r to the client. \a r must end with CR LF. */

void ImapSession::enqueue( const String & r )
{
    if ( d->i->session() != this ) {
        mailbox()->removeSession( this );
        return;
    }

    bool u = true;
    List<Command>::Iterator c( d->i->commands() );
    while ( c && u ) {
        if ( c->state() == Command::Executing ||
             c->state() == Command::Finished )
            u = false;
        ++c;
    }
    if ( u )
        d->unsolicited = true;
    d->i->enqueue( r );
}


/*! Records that \a f will be used by \a c. f \a c is the first
    Command to use \a f in this ImapSession, addFlags() uses
    Command::respond() to enqueue a FLAGS response announcing the new
    list of flags.
*/

void ImapSession::addFlags( List<Flag> * f, class Command * c )
{
    Scope x( d->l );
    List<Flag>::Iterator i( f );
    bool announce = false;
    while ( i ) {
        List<Flag>::Iterator j( d->flags );
        while ( j && j->id() < i->id() )
            ++j;
        if ( !j || j->id() > i->id() ) {
            d->flags.insert( j, i );
            announce = true;
        }
        ++i;
    }

    if ( !announce )
        return;

    String r;
    i = d->flags;
    while ( i ) {
        if ( !r.isEmpty() )
            r.append( " " );
        r.append( i->name() );
        ++i;
    }

    String s = "FLAGS (";
    s.append( r );
    s.append( ")" );
    if ( c ) {
        c->respond( s );
    }
    else {
        enqueue( "* " );
        enqueue( s );
        enqueue( "\r\n" );
    }

    s = "OK [PERMANENTFLAGS (";
    s.append( r );
    s.append( " \\*)] permanent flags" );
    if ( c ) {
        c->respond( s );
    }
    else {
        enqueue( "* " );
        enqueue( s );
        enqueue( "\r\n" );
    }
}


/*! Records that no flag/annotation/modseq update is to be sent for \a
    ms. ImapSession may send one anyway, but tries to avoid it.
*/

void ImapSession::ignoreModSeq( int64 ms )
{
    d->ignorable.append( new int64( ms ) );
}
