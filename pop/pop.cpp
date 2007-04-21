// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "pop.h"

#include "log.h"
#include "map.h"
#include "user.h"
#include "event.h"
#include "query.h"
#include "scope.h"
#include "string.h"
#include "buffer.h"
#include "mailbox.h"
#include "message.h"
#include "session.h"
#include "eventloop.h"
#include "popcommand.h"
#include "stringlist.h"
#include "transaction.h"
#include "configuration.h"


class PopData
    : public Garbage
{
public:
    PopData()
        : state( POP::Authorization ), sawUser( false ), user( 0 ),
          commands( new List< PopCommand > ), reader( 0 ),
          reserved( false ), session( 0 )
    {}

    POP::State state;

    bool sawUser;
    User * user;

    List< PopCommand > * commands;
    PopCommand * reader;
    bool reserved;
    Session * session;
    MessageSet toBeDeleted;
    Map<Message> messages;
};


static void newCommand( List< PopCommand > *, POP *,
                        PopCommand::Command, StringList * = 0 );


/*! \class POP pop.h
    This class implements a POP3 server.

    The Post Office Protocol is defined by RFC 1939, and updated by RFCs
    1957 (which doesn't say much) and 2449, which defines CAPA and other
    extensions. RFC 1734 defines an AUTH command for SASL authentication
    support, and RFC 2595 defines STARTTLS for POP3.
*/

/*! Creates a POP3 server for the fd \a s, and sends the initial banner.
*/

POP::POP( int s )
    : Connection( s, Connection::Pop3Server ),
      d( new PopData )
{
    ok( "Archiveopteryx POP3 server ready." );
    setTimeoutAfter( 600 );
    EventLoop::global()->addConnection( this );
}


/*! Sets this server's state to \a s, which may be one of Authorization,
    Transaction, or Update (as defined in POP3::State).

    If the state is set to Update, DELE actions are initiated.
    setState() returns immediately.
*/

void POP::setState( State s )
{
    if ( s == d->state )
        return;
    switch ( s ) {
    case Authorization:
        log( "Switching to Authorization state" );
        break;
    case Transaction:
        log( "Switching to Transaction state" );
        break;
    case Update:
        log( "Switching to Update state" );
        break;
    }
    if ( s == Update && user() && !d->toBeDeleted.isEmpty() ) {
        log( "Deleting " + fn( d->toBeDeleted.count() ) + " messages" );

        class PopDeleter
            : public EventHandler
        {
        private:
            User * user;
            Mailbox * mailbox;
            String w;
            ::Transaction * t;
            Query * nms;

        public:
            PopDeleter( User * u, Mailbox * m, const MessageSet & ms )
                : user( u ), mailbox( m ), w( ms.where() ),
                  t( 0 ), nms( 0 )
            {}

            void execute()
            {
                if ( !t ) {
                    t = new ::Transaction( this );
                    nms = new Query( "select nextmodseq from mailboxes "
                                     "where id=$1 for update", this );
                    nms->bind( 1, mailbox->id() );
                    t->enqueue( nms );
                    t->execute();
                }

                if ( nms ) {
                    if ( !nms->done() )
                        return;

                    uint ms( nms->nextRow()->getInt( "nextmodseq" ) );
                    nms = 0;

                    Query * q;
                    q = new Query( "update modsequences set modseq=$1 where "
                                   "mailbox=$2 and (" + w + ")", 0 );
                    q->bind( 1, ms );
                    q->bind( 2, mailbox->id() );
                    t->enqueue( q );

                    q = new Query( "insert into deleted_messages "
                                   "(mailbox, uid, deleted_by, reason) "
                                   "select mailbox, uid, $2, $3 "
                                   "from messages where mailbox=$1 and "
                                   "(" + w + ")", 0 );
                    q->bind( 1, mailbox->id() );
                    q->bind( 2, user->id() );
                    q->bind( 3, "POP delete " + Scope::current()->log()->id() );
                    t->enqueue( q );

                    q = new Query( "update mailboxes set "
                                   "nextmodseq=nextmodseq+1 where id=$1",
                                   this );
                    q->bind( 1, mailbox->id() );
                    t->enqueue( q );
                    t->commit();
                }

                if ( !t->done() )
                    return;

                if ( t->failed() )
                    log( "Error deleting messages: " + t->error() );
            }
        };

        PopDeleter * pd = new PopDeleter( d->user, d->session->mailbox(),
                                          d->toBeDeleted );
        pd->execute();
    }
    d->state = s;
}


/*! Returns the server's current state. */

POP::State POP::state() const
{
    return d->state;
}


void POP::react( Event e )
{
    switch ( e ) {
    case Read:
        setTimeoutAfter( 600 );
        parse();
        break;

    case Timeout:
        // We may not send any response.
        log( "Idle timeout" );
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        break;

    case Shutdown:
        // RFC 1939 says that if the server times out, it should close
        // silently. It doesn't talk about server shutdown, so it
        // sounds sensible to do nothing in that case as well.
        break;
    }

    if ( d->state == Update )
        Connection::setState( Closing );
    if ( Connection::state() == Closing && session() )
        session()->end();
}


/*! Parses POP3 client commands. */

void POP::parse()
{
    Buffer *b = readBuffer();

    while ( b->size() > 0 ) {
        if ( !d->reader ) {
            if ( d->reserved )
                break;

            String *s = b->removeLine( 255 );

            if ( !s ) {
                log( "Connection closed due to overlong line (" +
                     fn( b->size() ) + " bytes)", Log::Error );
                err( "Line too long. Closing connection." );
                Connection::setState( Closing );
                return;
            }

            bool unknown = false;

            StringList * args = StringList::split( ' ', *s );
            String cmd = args->take( args->first() )->lower();

            if ( d->sawUser && !( cmd == "quit" || cmd == "pass" ) ) {
                d->sawUser = false;
                unknown = true;
            }
            else if ( cmd == "quit" && args->isEmpty() ) {
                newCommand( d->commands, this, PopCommand::Quit );
            }
            else if ( cmd == "capa" && args->isEmpty() ) {
                newCommand( d->commands, this, PopCommand::Capa );
            }
            else if ( d->state == Authorization ) {
                if ( cmd == "stls" ) {
                    if ( hasTls() )
                        err( "Nested STLS" );
                    else
                        newCommand( d->commands, this, PopCommand::Stls );
                }
                else if ( cmd == "auth" ) {
                    newCommand( d->commands, this, PopCommand::Auth, args );
                }
                else if ( cmd == "user" && args->count() == 1 ) {
                    d->sawUser = true;
                    newCommand( d->commands, this, PopCommand::User, args );
                }
                else if ( d->sawUser && cmd == "pass" && args->count() == 1 ) {
                    d->sawUser = false;
                    newCommand( d->commands, this, PopCommand::Pass, args );
                }
                else {
                    unknown = true;
                }
            }
            else if ( d->state == Transaction ) {
                if ( cmd == "stat" && args->isEmpty() ) {
                    newCommand( d->commands, this, PopCommand::Stat );
                }
                else if ( cmd == "list" && args->count() < 2 ) {
                    newCommand( d->commands, this, PopCommand::List, args );
                }
                else if ( cmd == "top" && args->count() == 2 ) {
                    newCommand( d->commands, this, PopCommand::Top, args );
                }
                else if ( cmd == "retr" && args->count() == 1 ) {
                    newCommand( d->commands, this, PopCommand::Retr, args );
                }
                else if ( cmd == "dele" && args->count() == 1 ) {
                    newCommand( d->commands, this, PopCommand::Dele, args );
                }
                else if ( cmd == "noop" && args->isEmpty() ) {
                    newCommand( d->commands, this, PopCommand::Noop );
                }
                else if ( cmd == "rset" && args->isEmpty() ) {
                    newCommand( d->commands, this, PopCommand::Rset );
                }
                else if ( cmd == "uidl" && args->count() < 2 ) {
                    newCommand( d->commands, this, PopCommand::Uidl, args );
                }
                else {
                    unknown = true;
                }
            }
            else {
                unknown = true;
            }

            if ( unknown )
                err( "Bad command" );
        }
        else {
            d->reader->read();
        }

        runCommands();
    }
}


/*! Sends \a s as a positive +OK response. */

void POP::ok( const String &s )
{
    enqueue( "+OK " + s + "\r\n" );
}


/*! Sends \a s as a negative -ERR response. */

void POP::err( const String &s )
{
    enqueue( "-ERR " + s + "\r\n" );
    setReader( 0 );
}


/*! The POP server maintains a list of commands received from the
    client and processes them one at a time in the order they were
    received. This function executes the first command in the list,
    or if the first command has completed, removes it and executes
    the next one.

    It should be called when a new command has been created (i.e.,
    by POP::parse()) or when a running command finishes.
*/

void POP::runCommands()
{
    List< PopCommand >::Iterator it( d->commands );
    if ( !it )
        return;
    if ( it->done() )
        d->commands->take( it );
    if ( it )
        it->execute();
}


static void newCommand( List< PopCommand > * l, POP * pop,
                        PopCommand::Command cmd,
                        StringList * args )
{
    l->append( new PopCommand( pop, cmd, args ) );
}


/*! Sets the current user of this POP server to \a u. Called upon
    receipt of a valid USER command.
*/

void POP::setUser( User * u )
{
    log( "User " + u->login() );
    d->user = u;
}


/*! Returns the current user of this POP server, or an empty string if
    setUser() has never been called upon receipt of a USER command.
*/

User * POP::user() const
{
    return d->user;
}


/*! Reserves the input stream to inhibit parsing if \a r is true. If
    \a r is false, then the server processes input as usual. Used by
    STLS to inhibit parsing.
*/

void POP::setReserved( bool r )
{
    d->reserved = r;
}


/*! Reserves the input stream for processing by \a cmd, which may be 0
    to indicate that the input should be processed as usual. Used by
    AUTH to parse non-command input.
*/

void POP::setReader( PopCommand * cmd )
{
    d->reader = cmd;
    d->reserved = d->reader;
}


/*! Sets this POP server's Session object to \a s. */

void POP::setSession( Session * s )
{
    log( "Using mailbox " + s->mailbox()->name() );
    d->session = s;
}


/*! Returns this POP server's Session object, or 0 if none has been
    specified with setSession.
*/

Session * POP::session() const
{
    return d->session;
}


/*! Records that message \a uid should be deleted when the POP server
    goes into Update state.

    This is not written anywhere; the deletion state is kept in RAM
    only. If the client breaks the connection off, we don't delete.
*/

void POP::markForDeletion( uint uid )
{
    d->toBeDeleted.add( uid );
}


/*! This is used by PopCommand::user() to reset "sawUser" if a previous
    USER command failed. This is needed so that subsequent USER commands
    are not incorrectly rejected.
*/

void POP::badUser()
{
    d->sawUser = false;
}


/*! Returns a pointer to the Message object with UID \a uid, creating
    one if there isn't any.
*/

class Message * POP::message( uint uid )
{
    Message * m = d->messages.find( uid );
    if ( m )
        return m;
    m = new Message;
    m->setUid( uid );
    d->messages.insert( uid, m );
    return m;
}
