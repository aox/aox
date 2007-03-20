// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "imapsession.h"

#include "command.h"
#include "mailbox.h"
#include "message.h"
#include "imap.h"
#include "flag.h"


class ImapSessionData
    : public Garbage
{
public:
    ImapSessionData(): i( 0 ), unsolicited( 0 ), recent( UINT_MAX ) {}
    class IMAP * i;
    MessageSet expungedFetched;
    uint unsolicited;
    uint recent;
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


void ImapSession::emitExpunge( uint msn )
{
    enqueue( "* " + fn( msn ) + " EXPUNGE\r\n" );
    d->expungedFetched.clear();
}


void ImapSession::emitExists( uint number )
{
    enqueue( "* " + fn( number ) + " EXISTS\r\n" );

    uint r = recent().count();
    if ( d->recent != r ) {
        d->recent = r;
        enqueue( "* " + fn( r ) + " RECENT\r\n" );
    }

    uint n = uidnext();
    if ( n > announced() ) {
        enqueue( "* OK [UIDNEXT " + fn( n ) + "] next uid\r\n" );
        setAnnounced( n );
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


void ImapSession::emitModification( Message * m )
{
    if ( !m )
        return;
    if ( !m->hasFlags() )
        return;

    String r = "* ";
    r.append( fn( msn( m->uid() ) ) );
    r.append( " FETCH (UID " );
    r.append( fn( m->uid() ) );
    if ( d->i->clientSupports( IMAP::Condstore ) && m->modSeq() ) {
        r.append( " MODSEQ (" );
        r.append( fn( m->modSeq() ) );
        r.append( ")" );
    }
    r.append( " FLAGS (" );

    if ( isRecent( m->uid() ) )
        r = "\\recent";

    List<Flag> * f = m->flags();
    if ( f && !f->isEmpty() ) {
        List<Flag>::Iterator it( f );
        while ( it ) {
            if ( !r.isEmpty() )
                r.append( " " );
            r.append( it->name() );
            ++it;
        }
    }

    r.append( "))\r\n" );
    enqueue( r );
}


/*! Returns true we ca send all the \a type responses we need to, and
    false if we're missing any necessary data.
*/

bool ImapSession::responsesReady( ResponseType type ) const
{
    bool r = Session::responsesReady( type );
    if ( type == Modified ) {
        List<Message>::Iterator i( modifiedMessages() );
        while ( i && r ) {
            if ( !i->hasFlags() )
                r = false;
            if ( r && d->i->clientSupports( IMAP::Annotate ) &&
                 !i->hasAnnotations() )
                r = false;
            if ( r && d->i->clientSupports( IMAP::Annotate ) &&
                 !i->modSeq() )
                r = false;
            ++i;
        }
    }
    return r;
}


/*! Returns true if the server is permitted (and able) to send an
    unsolicited status response of type \a t for message \a m, and
    false otherwise.
*/

bool ImapSession::responsesPermitted( Message * m, ResponseType t ) const
{
    List<Command>::Iterator c( d->i->commands() );
    // if we're currently executing something other than idle, we
    // don't emit anything
    if ( c && c->state() != Command::Finished && c->name() != "idle" )
        return false;

    if ( t == Deleted ) {
        while ( c ) {
            // if there are MSNs in the pipeline we cannot send
            // expunge. the copy rule is due to RFC 2180 section
            // 4.4.1/2
            if ( c->usesMsn() && c->name() != "copy" )
                return false;
            // the search rule is due to a mistake in 3501
            if ( c->name() == "search" )
                return false;
            ++c;
        }
        return true;
    }
    else {
        if ( t == Modified && m ) {
            if ( !m->hasFlags() )
                return false;
            if ( d->i->clientSupports( IMAP::Annotate ) &&
                 !m->hasAnnotations() )
                return false;
            if ( d->i->clientSupports( IMAP::Annotate ) &&
                 !m->modSeq() )
                return false;
        }
        if ( !c ) {
            // no commands at all. have we sent anything?
            if ( d->unsolicited > 512 )
                return false;
            return true;
        }
        if ( c->state() == Command::Executing && c->name() == "idle" )
            return true;
        if ( c->state() == Command::Finished )
            return true;
        return false;
    }
}


/*! Sends \a r to the client. \a r must end with CR LF. */

void ImapSession::enqueue( const String & r )
{
    if ( d->i->session() != this ) {
        mailbox()->removeSession( this );
        return;
    }

    if ( d->i->commands()->isEmpty() )
        d->unsolicited += r.length();
    else
        d->unsolicited = 0;

    d->i->enqueue( r );
}


/*! This reimplementation tells the IMAP server that it can go on
    after emitting the responses, if indeed the IMAP server can go on.
*/

void ImapSession::emitResponses()
{
    Session::emitResponses();
    List<Command>::Iterator c( d->i->commands() );
    if ( c && c->state() == Command::Finished )
        d->i->unblockCommands();
}
