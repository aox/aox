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
    : public EventHandler
{
public:
    ImapSessionData(): i( 0 ), unsolicited( 0 ),
                       recent( UINT_MAX ),
                       uidnext( 0 ),
                       hms( 0 ), flagf( 0 ), annof( 0 ), trif( 0 ) {}
    class IMAP * i;
    MessageSet expungedFetched;
    uint unsolicited;
    uint recent;
    uint uidnext;
    List<int64> ignorable;
    int64 hms;

    Fetcher * flagf;
    Fetcher * annof;
    Fetcher * trif;

    // XXX: A hack. maybe Session should inherit EventHandler instead.
    void execute() {
        if ( flagf && flagf->done() )
            flagf = 0;
        if ( annof && annof->done() )
            annof = 0;
        if ( trif && trif->done() )
            trif = 0;
        if ( !flagf && !annof && !trif ) {
            i->unblockCommands();
            if ( i->idle() && i->session() )
                i->session()->emitResponses();
        }
    }
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


void ImapSession::emitModification( Message * m )
{
    if ( !m )
        return;
    if ( !m->hasFlags() )
        return;

    if ( m->modSeq() ) {
        if ( m->modSeq() > d->hms )
            d->hms = m->modSeq();
        List<int64>::Iterator i( d->ignorable );
        while ( i ) {
            if ( m->modSeq() == *i )
                return;
            ++i;
        }
    }

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
    r.append( Fetch::flagList( m, m->uid(), this ) );
    r.append( ")" );

    if ( d->i->clientSupports( IMAP::Annotate ) ) {
        r.append( " ANNOTATION " );
        // XXX: if we're doing this a lot, maybe we want to store e
        // and a in ImapSessionData
        StringList e;
        e.append( "*" );
        StringList a;
        a.append( "value.priv" );
        a.append( "value.shared" );
        r.append( Fetch::annotation( m, d->i->user(), e, a ) );
    }

    r.append( ")\r\n" );
    enqueue( r );
}


/*! Returns true we can send all the \a type responses we need to, and
    false if we're missing any necessary data.
*/

bool ImapSession::responsesReady( ResponseType type ) const
{
    if ( !Session::responsesReady( type ) )
        return false;

    List<Message>::Iterator i;
    if ( type == Modified )
        i = modifiedMessages();

    List<Message> * fl = new List<Message>;
    List<Message> * al = 0;
    if ( d->i->clientSupports( IMAP::Annotate ) )
        al = new List<Message>;
    List<Message> * tl = 0;
    if ( d->i->clientSupports( IMAP::Condstore ) ||
         !d->ignorable.isEmpty() )
        tl = new List<Message>;
    while ( i ) {
        if ( fl && !i->hasFlags() )
            fl->append( i );
        if ( al && !i->hasAnnotations() )
            al->append( i );
        if ( tl && !i->modSeq() )
            tl->append( i );
        ++i;
    }

    if ( ( !fl || fl->isEmpty() ) && 
         ( !al || al->isEmpty() ) && 
         ( !tl || tl->isEmpty() ) )
        return true;

    if ( fl && !fl->isEmpty() ) {
        if ( !d->flagf )
            d->flagf = new MessageFlagFetcher( mailbox(), fl, d );
        else if ( d->flagf->done() )
            d->flagf->addMessages( fl );
        d->flagf->execute();
    }
    if ( al && !al->isEmpty() ) {
        if ( !d->annof )
            d->annof = new MessageAnnotationFetcher( mailbox(), al, d );
        else if ( d->annof->done() )
            d->annof->addMessages( al );
        d->annof->execute();
    }
    if ( tl && !tl->isEmpty() ) {
        if ( !d->trif )
            d->trif = new MessageTriviaFetcher( mailbox(), tl, d );
        else if ( d->trif->done() )
            d->trif->addMessages( tl );
        d->trif->execute();
    }

    return false;
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
        if ( !c ) {
            // no commands at all. have we sent anything?
            if ( d->unsolicited > 512 )
                return false;
            // not so much. we can send a little more.
            return true;
        }

        // is there a finished command we may stuff with responses?
        while ( c && c->state() != Command::Finished )
            ++c;
        if ( c )
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
    while ( c && c->state() == Command::Retired )
        ++c;
    if ( c && c->state() == Command::Finished &&
         !d->flagf && !d->annof && !d->trif )
        d->i->unblockCommands();

    List<int64>::Iterator i( d->ignorable );
    while ( i ) {
        if ( *i < d->hms )
            d->ignorable.take( i );
        else
            ++i;
    }
}


/*! Instructs this ImapSession to emit no responses for messages whose
    Message::modSeq() is \a ms.

    This is used by Store to implement its "silent" feature.
*/

void ImapSession::ignoreModSeq( int64 ms )
{
    int64 * i = new int64;
    *i = ms;
    d->ignorable.append( i );
}
