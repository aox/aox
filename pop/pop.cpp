// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "pop.h"

#include "log.h"
#include "map.h"
#include "user.h"
#include "event.h"
#include "query.h"
#include "scope.h"
#include "entropy.h"
#include "estring.h"
#include "buffer.h"
#include "mailbox.h"
#include "message.h"
#include "session.h"
#include "selector.h"
#include "eventloop.h"
#include "popcommand.h"
#include "estringlist.h"
#include "transaction.h"
#include "configuration.h"


class PopData
    : public Garbage
{
public:
    PopData()
        : state( POP::Authorization ), sawUser( false ),
          commands( new List< PopCommand > ), reader( 0 ),
          reserved( false ), messages( 0 )
    {}

    POP::State state;

    bool sawUser;

    List< PopCommand > * commands;
    PopCommand * reader;
    bool reserved;
    IntegerSet toBeDeleted;
    Map<Message> * messages;
    EString challenge;
};


static void newCommand( List< PopCommand > *, POP *,
                        PopCommand::Command, EStringList * = 0 );


static EString randomChallenge()
{
    EString hn( Configuration::hostname() );
    EString random( Entropy::asString( 12 ).e64() );

    if ( hn.isEmpty() || hn.find( '.' ) < 0 )
        hn = "aox.invalid";

    return "<" + random + "@" + hn + ">";
}


/*! \class POP pop.h
    This class implements a POP3 server.

    The Post Office Protocol is defined by RFC 1939, and updated by
    RFC 1957 (which doesn't say much) and RFC 2449, which defines CAPA
    and other extensions. RFC 1734 defines an AUTH command for SASL
    authentication support, and RFC 2595 defines STARTTLS for POP3.
*/

/*! Creates a POP3 server for the fd \a s, and sends the initial banner.
*/

POP::POP( int s )
    : SaslConnection( s, Connection::Pop3Server ),
      d( new PopData )
{
    d->challenge = randomChallenge();
    ok( "Archiveopteryx POP3 server ready " + d->challenge );
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
            IntegerSet s;
            ::Transaction * t;
            Query * nms;
            RetentionSelector * r;
            Query * iq;
            int64 ms;

        public:
            PopDeleter( User * u, Mailbox * m, const IntegerSet & ms )
                : user( u ), mailbox( m ), s( ms ),
                  t( 0 ), nms( 0 ), r( 0 ), iq( 0 ), ms( 0 )
            {}

            void execute()
            {
                if ( !r ) {
                    r = new RetentionSelector( mailbox, this );
                    r->execute();
                }

                if ( !t ) {
                    t = new ::Transaction( this );
                    nms = new Query( "select nextmodseq from mailboxes "
                                     "where id=$1 for update", this );
                    nms->bind( 1, mailbox->id() );
                    t->enqueue( nms );
                    t->execute();
                }

                if ( nms ) {
                    if ( !r->done() )
                        return;

                    if ( !nms->done() )
                        return;

                    ms = nms->nextRow()->getBigint( "nextmodseq" );
                    nms = 0;

                    Selector * s = new Selector;
                    if ( r->retains() ) {
                        Selector * n = new Selector( Selector::Not );
                        s->add( n );
                        n->add( r->retains() );
                    }
                    s->add( new Selector( this->s ) );
                    s->simplify();
                    EStringList wanted;
                    wanted.append( "mailbox" );
                    wanted.append( "uid" );
                    wanted.append( "message" );
                    iq = s->query( 0, mailbox, 0, this, false,
                                   &wanted, false );
                    int i = iq->string().find( " from " );
                    uint msb = s->placeHolder();
                    uint ub = s->placeHolder();
                    uint rb = s->placeHolder();
                    iq->setString(
                        "insert into deleted_messages "
                        "(mailbox,uid,message,modseq,deleted_by,reason) " +
                        iq->string().mid( 0, i ) + ", $" + fn( msb ) +", $" +
                        fn( ub ) + ", $" + fn( rb ) + iq->string().mid( i ) );
                    iq->bind( msb, ms );
                    iq->bind( ub, user->id() );
                    iq->bind( rb,
                             "POP delete " + Scope::current()->log()->id() );
                    t->enqueue( iq );
                    t->execute();
                }

                if ( iq ) {
                    if ( !iq->done() )
                        return;

                    if ( iq->rows() ) {
                        // at least one message was deleted
                        Query * q = new Query( "update mailboxes set "
                                               "nextmodseq=$1 where id=$2",
                                               this );
                        q->bind( 1, ms+1 );
                        q->bind( 2, mailbox->id() );
                        t->enqueue( q );
                        Mailbox::refreshMailboxes( t );
                    }
                    iq = 0;
                    t->commit();
                }

                if ( !t->done() )
                    return;

                if ( t->failed() )
                    log( "Error deleting messages: " + t->error() );
            }
        };

        session()->earlydeletems( d->toBeDeleted );

        PopDeleter * pd = new PopDeleter( user(), session()->mailbox(),
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
        break;

    case Error:
        Connection::setState( Closing );
        break;

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
}


/*! Parses POP3 client commands. */

void POP::parse()
{
    Buffer *b = readBuffer();

    while ( b->size() > 0 ) {
        if ( !d->reader ) {
            if ( d->reserved )
                break;

            EString * s = b->removeLine( 255 );

            if ( !s && b->size() < 255 )
                return;

            if ( !s ) {
                log( "Connection closed due to overlong line (" +
                     fn( b->size() ) + " bytes)", Log::Error );
                err( "Line too long. Closing connection." );
                Connection::setState( Closing );
                return;
            }

            bool unknown = false;

            EStringList * args = EStringList::split( ' ', *s );
            EString cmd = args->take( args->first() )->lower();

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
                else if ( d->sawUser && cmd == "pass" && args->count() >= 1 ) {
                    d->sawUser = false;
                    newCommand( d->commands, this, PopCommand::Pass, args );
                }
                else if ( cmd == "apop" && args->count() == 2 ) {
                    newCommand( d->commands, this, PopCommand::Apop, args );
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

            if ( unknown ) {
                err( "Bad command" );
                recordSyntaxError();
            }
        }
        else {
            d->reader->read();
        }

        runCommands();
    }
}


/*! Sends \a s as a positive +OK response. */

void POP::ok( const EString &s )
{
    enqueue( "+OK " + s + "\r\n" );
}


/*! Sends \a s as a negative -ERR response. */

void POP::err( const EString &s )
{
    enqueue( "-ERR " + s + "\r\n" );
    setReader( 0 );
}

/*! Sends \a s as a negative -ERR response and drops the connection. */

void POP::abort( const EString &s )
{
    err( s );
    react( Error );
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
                        EStringList * args )
{
    l->append( new PopCommand( pop, cmd, args ) );
}


void POP::setUser( User * u, const EString & m )
{
    log( "Authenticated as user " + u->login().ascii(), Log::Significant );
    SaslConnection::setUser( u, m );
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


/*! Returns a pointer to the Message object with UID \a uid, or 0 if
    there isn't any.
*/

class Message * POP::message( uint uid )
{
    if ( !d->messages )
        return 0;
    return d->messages->find( uid );
}


void POP::sendChallenge( const EString &s )
{
    enqueue( "+ "+ s +"\r\n" );
}


/*! Records the Message objects needed for this Pop session. Each of
    the Message objects is presumed to know its database ID, and may
    know more. \a m is a map from UID to Message objects.
*/

void POP::setMessageMap( Map<Message> * m )
{
    d->messages = m;
}


/*! Returns the challenge sent at the beginning of this connection for
    use with APOP authentication. */

EString POP::challenge() const
{
    return d->challenge;
}


/*! \class POPS pop.h
    Implements SSL-wrapped POP3
*/

POPS::POPS( int s )
    : POP( s )
{
    EString * tmp = writeBuffer()->removeLine();
    startTls();
    enqueue( *tmp + "\r\n" );
}
