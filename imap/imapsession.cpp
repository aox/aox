// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "handlers/fetch.h"
#include "command.h"
#include "fetcher.h"
#include "mailbox.h"
#include "message.h"
#include "imap.h"
#include "flag.h"


class ImapSessionData
    : public Garbage
{
public:
    ImapSessionData(): i( 0 ), unsolicited( false ),
                       exists( UINT_MAX/4 ), recent( UINT_MAX ),
                       uidnext( 0 ) {}
    class IMAP * i;
    MessageSet expungedFetched;
    bool unsolicited;
    uint exists;
    uint recent;
    uint uidnext;
    List<Flag> flags;
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
}


ImapSession::~ImapSession()
{
}


/*! Returns a pointer to the IMAP connection that's using this session. */

IMAP * ImapSession::imap() const
{
    return d->i;
}


void ImapSession::emitExpunges()
{
    MessageSet m;
    m.add( messages() );

    MessageSet e;
    e.add( expunged() );
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
}


void ImapSession::emitExists( uint number )
{
    if ( d->exists != number )
        enqueue( "* " + fn( number ) + " EXISTS\r\n" );

    if ( d->unsolicited ) {
        List<Command>::Iterator c( d->i->commands() );
        while ( c && c->state() == Command::Retired )
            ++c;
        if ( c && c->state() == Command::Finished )
            d->unsolicited = false;
        else
            return;
    }
    d->exists = number;

    uint r = recent().count();
    if ( d->recent != r ) {
        d->recent = r;
        enqueue( "* " + fn( r ) + " RECENT\r\n" );
    }

    uint n = uidnext();
    if ( n > d->uidnext ) {
        d->uidnext = n;
        enqueue( "* OK [UIDNEXT " + fn( n ) + "] next uid\r\n" );
    }
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

    enqueue( "* BYE These messages have been expunged: " +
             set.set() + "\r\n" );
    d->i->setState( IMAP::Logout );
}


void ImapSession::emitModifications()
{
    MessageSet changed( unannounced().intersection( messages() ) );
    // don't bother sending updates about something that's already gone,
    // for which we just haven't sent the expunge
    changed.remove( expunged() );

    if ( changed.isEmpty() )
        return;

    Fetch * update 
        = new Fetch( true, d->i->clientSupports( IMAP::Annotate ),
                     changed, nextModSeq() - 1, d->i );

    List<Command>::Iterator c( d->i->commands() );
    while ( c && c->state() == Command::Retired )
        ++c;
    if ( c && c->state() == Command::Finished ) {
        List<Command>::Iterator n( c );
        ++n;
        d->i->commands()->insert( n, update );
        c->moveTaggedResponseTo( update );
    }
    else {
        d->i->commands()->append( update );
    }
    update->execute();
}


/*! This reimplementation exists because we sometimes want to send
    reminders in IMAP: If a message arrives while the client isn't
    doing anything, we want to tell it right away, and remind it when
    it next sends a command.

    Apparently some clients don't listen when we tell them, but do
    listen to the reminder.

    The reimplementation does nothing if \a t is not 'New'.
*/

bool ImapSession::responsesNeeded( ResponseType t ) const
{
    if ( t == New && d->unsolicited ) {
        List<Command>::Iterator c( d->i->commands() );
        while ( c && c->state() == Command::Retired )
            ++c;
        if ( c && c->state() == Command::Finished )
            return true;
    }
    return Session::responsesNeeded( t );
}



/*! Returns true if the server is permitted (and able) to send an
    unsolicited status responses of type \a t, and false otherwise.
*/

bool ImapSession::responsesPermitted( ResponseType t ) const
{
    if ( d->i->idle() )
        return true;

    List<Command>::Iterator c( d->i->commands() );
    while ( c && c->state() == Command::Retired )
        ++c;

    if ( t == Deleted ) {
        if ( !c )
            return false;
        while ( c ) {
            // we don't need to consider retired commands at all
            if ( c->state() == Command::Retired )
                ;
            // we cannot send an expunge while a command is being
            // executed (not without NOTIFY at least...)
            else if ( c->state() == Command::Executing )
                return false;
            // group 2 contains commands during which we may not send
            // expunge, group 3 contains all commands that change
            // flags.
            else if ( c->group() == 2 || c->group() == 3 )
                return false;
            // if there are MSNs in the pipeline we cannot send
            // expunge. the copy rule is due to RFC 2180 section
            // 4.4.1/2
            else if ( c->usesMsn() && c->name() != "copy" )
                return false;
            ++c;
        }
        return true;
    }
    else {
        if ( t == New && !c ) {
            // no commands at all. have we sent anything?
            if ( !d->unsolicited )
                return true;
            return false;
        }
        
        bool finished = false;
        bool executing = false;
        while ( c ) {
            if ( c->state() == Command::Finished )
                finished = true;
            else if ( c->state() == Command::Executing )
                executing = true;
            ++c;
        }
        if ( executing )
            return false; // no responses while commands are running
        if ( finished )
            return true; // we can stuff responses onto that command

        return false; // no command in progress
    }
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


/*! This reimplementation tells the IMAP server that it can go on
    after emitting the responses, if indeed the IMAP server can go on.
*/

void ImapSession::emitResponses()
{
    Session::emitResponses();
    List<Command>::Iterator c( d->i->commands() );
    while ( c && c->state() == Command::Retired )
        ++c;
    if ( c && c->state() == Command::Finished )
        d->i->unblockCommands();
}


/*! Records that \a f will be used by \a c. f \a c is the first
    Command to use \a f in this ImapSession, addFlags() uses
    Command::respond() to enqueue a FLAGS response announcing the new
    list of flags.
*/

void ImapSession::addFlags( List<Flag> * f, class Command * c )
{
    List<Flag>::Iterator i( f );
    bool announce = false;
    while ( i ) {
        List<Flag>::Iterator j( d->flags );
        while ( j && j->id() < i->id() )
            ++j;
        if ( !j || i->id() > i->id() ) {
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
