// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "popcommand.h"

#include "tls.h"
#include "user.h"
#include "plain.h"
#include "buffer.h"
#include "message.h"
#include "session.h"
#include "mailbox.h"
#include "mechanism.h"
#include "stringlist.h"
#include "permissions.h"


class PopCommandData
    : public Garbage
{
public:
    PopCommandData()
        : pop( 0 ), args( 0 ), done( false ),
          tlsServer( 0 ), m( 0 ), r( 0 ),
          user( 0 ), mailbox( 0 ), permissions( 0 ),
          session( 0 ), sentFetch( false ), started( false ),
          message( 0 )
    {}

    POP * pop;
    PopCommand::Command cmd;
    StringList * args;

    bool done;

    TlsServer * tlsServer;
    SaslMechanism * m;
    String * r;
    User * user;
    Mailbox * mailbox;
    Permissions * permissions;
    Session * session;
    MessageSet set;
    bool sentFetch;
    bool started;
    Message * message;
};


/*! \class PopCommand popcommand.h
    This class represents a single POP3 command. It is analogous to an
    IMAP Command, except that it does all the work itself, rather than
    leaving it to subclasses.
*/


/*! Creates a new PopCommand object representing the command \a cmd, for
    the POP server \a pop.
*/

PopCommand::PopCommand( POP * pop, Command cmd, StringList * args )
    : d( new PopCommandData )
{
    d->pop = pop;
    d->cmd = cmd;
    d->args = args;
}


/*! Marks this command as having finished execute()-ing. Any responses
    are written to the client, and the POP server is instructed to move
    on to processing the next command.
*/

void PopCommand::finish()
{
    d->done = true;
    d->pop->write();
    d->pop->runCommands();
}


/*! Returns true if this PopCommand has finished executing, and false if
    execute() hasn't been called, or if it has work left to do. Once the
    work is done, execute() calls finish() to signal completion.
*/

bool PopCommand::done()
{
    return d->done;
}


/*! Tries to read a single response line from the client. Upon return,
    d->r points to the response, or is 0 if no response could be read.
*/

void PopCommand::read()
{
    d->r = d->pop->readBuffer()->removeLine();
}


void PopCommand::execute()
{
    switch ( d->cmd ) {
    case Quit:
        log( "Closing connection due to QUIT command", Log::Debug );
        d->pop->setState( POP::Update );
        d->pop->ok( "Goodbye" );
        break;

    case Capa:
        d->pop->ok( "Capabilities:" );
        d->pop->enqueue( // "TOP\r\n"
                         "SASL\r\n"
                         "STLS\r\n"
                         "USER\r\n"
                         "RESP-CODES\r\n"
                         "PIPELINING\r\n"
                         // "UIDL\r\n"
                         "IMPLEMENTATION Archiveopteryx POP3 Server, "
                         "http://www.archiveopteryx.org.\r\n"
                         ".\r\n" );
        break;

    case Stls:
        if ( !startTls() )
            return;
        break;

    case Auth:
        if ( !auth() )
            return;
        break;

    case User:
        if ( !user() )
            return;
        break;

    case Pass:
        if ( !pass() )
            return;
        break;

    case Session:
        if ( !session() )
            return;
        break;

    case Stat:
        if ( !stat() )
            return;
        break;

    case List:
        if ( !list() )
            return;
        break;

    case Retr:
        if ( !retr() )
            return;
        break;

    case Dele:
        if ( !dele() )
            return;
        break;

    case Noop:
        d->pop->ok( "Done" );
        break;

    case Rset:
        d->pop->ok( "Done" );
        break;
    }

    finish();
}


/*! Handles the STLS command. */

bool PopCommand::startTls()
{
    if ( !d->tlsServer ) {
        d->tlsServer = new TlsServer( this, d->pop->peer(), "POP" );
        d->pop->setReserved( true );
    }

    if ( !d->tlsServer->done() )
        return false;

    d->pop->ok( "Done" );
    d->pop->setReserved( false );
    d->pop->write();
    d->pop->startTls( d->tlsServer );

    return true;
}


/*! Handles the AUTH command. */

bool PopCommand::auth()
{
    if ( !d->m ) {
        String t = nextArg().lower();
        if ( d->pop->supports( t ) )
            d->m = SaslMechanism::create( t, this );
        if ( !d->m ) {
            d->pop->err( "SASL mechanism " + t + " not supported" );
            return true;
        }
        d->pop->setReader( this );

        String r = nextArg();
        if ( d->m->state() == SaslMechanism::AwaitingInitialResponse ) {
            if ( !r.isEmpty() )
                d->m->readResponse( d->r->de64() );
            else
                d->m->setState( SaslMechanism::IssuingChallenge );
        }
    }

    // This code is essentially a copy of imapd/handlers/authenticate.
    // I'll think about how to avoid the duplication later.
    while ( !d->m->done() ) {
        if ( d->m->state() == SaslMechanism::IssuingChallenge ) {
            String c = d->m->challenge().e64();

            if ( !d->m->done() ) {
                d->pop->enqueue( "+ "+ c +"\r\n" );
                d->m->setState( SaslMechanism::AwaitingResponse );
                d->r = 0;
                return false;
            }
        }
        else if ( d->m->state() == SaslMechanism::AwaitingResponse ) {
            if ( !d->r ) {
                return false;
            }
            else if ( *d->r == "*" ) {
                d->m->setState( SaslMechanism::Terminated );
            }
            else {
                d->m->readResponse( d->r->de64() );
                d->r = 0;
                if ( !d->m->done() ) {
                    d->m->execute();
                    if ( d->m->state() == SaslMechanism::Authenticating )
                        return false;
                }
            }
        }
    }

    if ( !d->m->done() )
        return false;

    if ( d->m->state() == SaslMechanism::Succeeded ) {
        d->pop->setReader( 0 );
        d->pop->setUser( d->m->user() );
        d->cmd = Session;
        return session();
    }
    else if ( d->m->state() == SaslMechanism::Terminated ) {
        d->pop->err( "Authentication terminated" );
    }
    else {
        d->pop->err( "Authentication failed" );
    }

    return true;
}


/*! Handles the USER command. */

bool PopCommand::user()
{
    if ( !d->user ) {
        d->user = new ::User;
        d->pop->setUser( d->user );
        d->user->setLogin( nextArg() );
        d->user->refresh( this );
    }

    if ( d->user->state() == User::Unverified )
        return false;

    if ( d->user->state() == User::Nonexistent )
        d->pop->err( "No such user" );
    else
        d->pop->ok( "Done" );

    return true;
}


/*! Handles the PASS command. */

bool PopCommand::pass()
{
    if ( !d->m ) {
        d->m = new Plain( this );
        d->m->setLogin( d->pop->user()->login() );
        d->m->setSecret( nextArg() );
        d->m->execute();
    }

    if ( !d->m->done() )
        return false;

    if ( d->m->state() == SaslMechanism::Succeeded )
        return session();

    d->pop->err( "Authentication failed" );
    return true;
}


/*! Acquires a Session object for the POP server when it enters
    Transaction state.
*/

bool PopCommand::session()
{
    if ( !d->mailbox ) {
        d->mailbox = d->pop->user()->inbox();
        d->permissions =
            new Permissions( d->mailbox, d->pop->user(), this );
    }

    if ( !d->permissions->ready() )
        return false;

    if ( !d->session ) {
        if ( !d->permissions->allowed( Permissions::Read ) ) {
            d->pop->err( "Insufficient privileges" );
            return true;
        }
        else {
            bool ro = true;
            if ( d->permissions->allowed( Permissions::KeepSeen ) &&
                 d->permissions->allowed( Permissions::DeleteMessages ) &&
                 d->permissions->allowed( Permissions::Expunge ) )
                ro = false;
            d->session = new ::Session( d->mailbox, ro );
            d->session->setPermissions( d->permissions );
            d->pop->setSession( d->session );
            d->session->refresh( this );
        }
    }

    if ( !d->session->initialised() )
        return false;

    d->session->clearExpunged();
    d->pop->setState( POP::Transaction );
    d->pop->ok( "Done" );
    return true;
}


/*! Handles the guts of the STAT/LIST data acquisition. If \a n is 0,
    then all messages in the Session are considered. Otherwise, only
    the size of message with the specified MSN is fetched.
*/

bool PopCommand::fetch822Size()
{
    ::Session * s = d->pop->session();

    uint n = d->set.count();
    while ( n >= 1 ) {
        uint uid = d->set.value( n );
        Message * m = s->mailbox()->message( uid );
        if ( m && !m->hasTrivia() )
            break;
        n--;
    }

    if ( n == 0 )
        return true;

    if ( !d->sentFetch ) {
        s->mailbox()->fetchTrivia( d->set, this );
        d->sentFetch = true;
    }

    return false;
}


/*! Handles the STAT command. */

bool PopCommand::stat()
{
    ::Session * s = d->pop->session();

    if ( !d->started ) {
        d->started = true;
        uint n = s->count();
        while ( n >= 1 ) {
            d->set.add( s->uid( n ) );
            n--;
        }
    }

    if ( !fetch822Size() )
        return false;

    uint size = 0;
    uint n = s->count();
    while ( n >= 1 ) {
        Message * m = s->mailbox()->message( s->uid( n ) );
        if ( m )
            size += m->rfc822Size();
        n--;
    }

    d->pop->ok( fn( s->count() ) + " " + fn( size ) );
    return true;
}


/*! Handles the LIST command. */

bool PopCommand::list()
{
    ::Session * s = d->pop->session();

    if ( !d->started ) {
        d->started = true;

        if ( d->args->count() == 0 ) {
            uint n = s->count();
            while ( n >= 1 ) {
                d->set.add( s->uid( n ) );
                n--;
            }
        }
        else {
            bool ok;
            String arg = *d->args->first();
            uint msn = arg.number( &ok );
            if ( !ok || msn < 1 || msn > s->count() ) {
                d->pop->err( "Bad message number" );
                return true;
            }
            d->set.add( s->uid( msn ) );
        }
    }

    if ( !fetch822Size() )
        return false;

    if ( d->args->count() == 1 ) {
        uint uid = d->set.smallest();
        Message * m = s->mailbox()->message( uid );

        if ( m )
            d->pop->ok( fn( s->msn( uid ) ) + " " +
                        fn( m->rfc822Size() ) );
        else
            d->pop->err( "No such message" );
    }
    else {
        uint i = 1;

        d->pop->ok( "Done" );
        while ( i <= d->set.count() ) {
            uint uid = d->set.value( i );
            Message * m = s->mailbox()->message( uid );
            if ( m )
                d->pop->enqueue( fn( s->msn( uid ) ) + " " +
                                 fn( m->rfc822Size() ) + "\r\n" );
            i++;
        }
        d->pop->enqueue( ".\r\n" );
    }
    return true;
}


/*! Handles the RETR command. */

bool PopCommand::retr()
{
    ::Session * s = d->pop->session();

    if ( !d->started ) {
        bool ok;
        uint msn = nextArg().number( &ok );
        if ( !ok || msn < 1 || msn > s->count() ||
             ( d->message = s->mailbox()->message( s->uid( msn ) ) ) == 0 )
        {
            d->pop->err( "Bad message number" );
            return true;
        }
        d->set.add( s->uid( msn ) );
        if ( !d->message->hasBodies() )
            s->mailbox()->fetchBodies( d->set, this );
        if ( !d->message->hasHeaders() )
            s->mailbox()->fetchHeaders( d->set, this );
        d->started = true;
    }

    if ( !( d->message->hasBodies() && d->message->hasHeaders() ) )
        return false;

    d->pop->ok( "Done" );

    Buffer * b = new Buffer;
    b->append( d->message->rfc822() );

    String * t;
    while ( ( t = b->removeLine() ) != 0 ) {
        if ( t->startsWith( "." ) )
            d->pop->enqueue( "." );
        d->pop->enqueue( *t );
        d->pop->enqueue( "\r\n" );
    }

    String st = b->string( b->size() );
    if ( !st.isEmpty() ) {
        if ( st.startsWith( "." ) )
            d->pop->enqueue( "." );
        d->pop->enqueue( st );
        d->pop->enqueue( "\r\n" );
    }

    d->pop->enqueue( ".\r\n" );
    return true;
}


/*! This function returns the next argument supplied by the client for
    this command, or an empty string if there are no more arguments.
    (Should we assume that nextArg will never be called more times
    than there are arguments? The POP parser does enforce this.)
*/

String PopCommand::nextArg()
{
    if ( d->args && !d->args->isEmpty() )
        return *d->args->take( d->args->first() );
    return "";
}


/*! Marks the specified message for later deletion. Although the RFC
    prohibits the client from marking the same message twice, we
    blithely allow it.

    The message is not marked in the database, since if it were, a
    different IMAP or POP command could delete it before this POP
    enters Update state.
*/

bool PopCommand::dele()
{
    bool ok;
    uint msn = nextArg().number( &ok );
    uint uid = 0;
    if ( ok )
        uid = d->pop->session()->uid( msn );
    if ( uid ) {
        d->pop->markForDeletion( uid );
        d->pop->ok( "Done" );
    }
    else {
        d->pop->err( "Invalid message number" );
    }
    return true;
}
