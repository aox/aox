// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "popcommand.h"

#include "md5.h"
#include "map.h"
#include "utf.h"
#include "list.h"
#include "user.h"
#include "plain.h"
#include "query.h"
#include "buffer.h"
#include "fetcher.h"
#include "message.h"
#include "session.h"
#include "mailbox.h"
#include "mechanism.h"
#include "estringlist.h"
#include "permissions.h"
#include "messagecache.h"


class PopCommandData
    : public Garbage
{
public:
    PopCommandData()
        : pop( 0 ), args( 0 ), done( false ),
          m( 0 ), r( 0 ),
          user( 0 ), mailbox( 0 ), permissions( 0 ),
          session( 0 ), sentFetch( false ), started( false ),
          message( 0 ), n( 0 ), findIds( 0 ), map( 0 )
    {}

    POP * pop;
    PopCommand::Command cmd;
    EStringList * args;

    bool done;

    SaslMechanism * m;
    EString * r;
    User * user;
    Mailbox * mailbox;
    Permissions * permissions;
    Session * session;
    IntegerSet set;
    bool sentFetch;
    bool started;
    Message * message;
    int n;

    Query * findIds;
    Map<Message> * map;

    class PopSession
        : public Session
    {
    public:
        PopSession( Mailbox * m, Connection * c, bool ro, PopCommand * pc )
            : Session( m, c, ro ), p( pc ) {}

        void emitUpdates( Transaction * ) { p->execute(); }

    private:
        class PopCommand * p;
    };
};


/*! \class PopCommand popcommand.h
    This class represents a single POP3 command. It is analogous to an
    IMAP Command, except that it does all the work itself, rather than
    leaving it to subclasses.
*/


/*! Creates a new PopCommand object representing the command \a cmd, for
    the POP server \a pop, with the arguments in \a args.
*/

PopCommand::PopCommand( POP * pop, Command cmd, EStringList * args )
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


/*! Tries to read a single response line from the client and pass it to
    the SaslMechanism.
*/

void PopCommand::read()
{
    d->m->readResponse( d->pop->readBuffer()->removeLine() );
}


void PopCommand::execute()
{
    if ( d->done )
        return;

    switch ( d->cmd ) {
    case Quit:
        log( "Closing connection due to QUIT command", Log::Debug );
        d->pop->setState( POP::Update );
        d->pop->ok( "Goodbye" );
        break;

    case Capa:
        {
            EString c( "TOP\r\n"
                      "UIDL\r\n"
                      "SASL\r\n"
                      "USER\r\n"
                      "RESP-CODES\r\n"
                      "PIPELINING\r\n"
                      "IMPLEMENTATION Archiveopteryx POP3 Server, "
                      "http://archiveopteryx.org.\r\n" );
            if ( Configuration::toggle( Configuration::UseTls ) )
                c.append( "STLS\r\n" );
            c.append( ".\r\n" );
            d->pop->ok( "Capabilities:" );
            d->pop->enqueue( c );
        }
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

    case Apop:
        if ( !apop() )
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

    case Top:
        if ( !retr( true ) )
            return;
        break;

    case Retr:
        if ( !retr( false ) )
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

    case Uidl:
        if ( !uidl() )
            return;
        break;
    }

    finish();
}


/*! Handles the STLS command. */

bool PopCommand::startTls()
{
    log( "STLS Command" );
    d->pop->ok( "Done" );
    d->pop->startTls();

    return true;
}


/*! Handles the AUTH command. */

bool PopCommand::auth()
{
    if ( !d->m ) {
        log( "AUTH Command" );
        EString t = nextArg().lower();
        d->m = SaslMechanism::create( t, this, d->pop );
        if ( !d->m ) {
            d->pop->err( "SASL mechanism " + t.quoted() + " not available" );
            return true;
        }

        EString s( nextArg() );
        EString * r = 0;
        if ( !s.isEmpty() )
            r = new EString( s );

        d->pop->setReader( this );
        d->m->readInitialResponse( r );
    }

    if ( !d->m->done() )
        return false;

    if ( d->m->state() == SaslMechanism::Succeeded ) {
        d->pop->setReader( 0 );
        d->pop->setUser( d->m->user(), d->m->name() );
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
        log( "USER Command" );
        if ( !d->pop->accessPermitted() ) {
            d->pop->err( "Must enable TLS before login" );
            return true;
        }
        d->user = new ::User;
        Utf8Codec c;
        d->user->setLogin( c.toUnicode( nextArg() ) );
        d->pop->setUser( d->user, "POP3 login" );
        if ( c.valid() ) {
            d->user->refresh( this );
        }
        else {
            d->pop->err( "Argument encoding error: " + c.error() );
            d->pop->badUser();
            return true;
        }
    }

    if ( d->user->state() == User::Unverified )
        return false;

    if ( d->user->state() == User::Nonexistent ) {
        d->pop->err( "No such user" );
        d->pop->badUser();
    }
    else {
        d->pop->ok( "Done" );
    }

    return true;
}


/*! Handles the PASS command. */

bool PopCommand::pass()
{
    if ( !d->m ) {
        log( "PASS Command" );
        d->m = SaslMechanism::create( "plain", this, d->pop );
        if ( !d->m ) {
            d->pop->err( "Plaintext authentication disallowed" );
            return true;
        }
        d->m->setState( SaslMechanism::Authenticating );
        d->m->setLogin( d->pop->user()->login() );
        EString pw=nextArg();
        while ( d->args->count() ) {
            pw += " ";
            pw += nextArg();
        }
        d->m->setSecret( pw );
        d->m->execute();
    }

    if ( !d->m->done() )
        return false;

    if ( d->m->state() == SaslMechanism::Succeeded )
        return session();

    d->pop->err( "Authentication failed" );
    return true;
}


/*! Handles APOP authentication. */

bool PopCommand::apop()
{
    class Apop
        : public Plain
    {
    public:
        Apop( EventHandler * ev, const UString & s )
            : Plain( ev ), challenge( s )
        {}

        void verify()
        {
            UString s( challenge );
            s.append( storedSecret() );

            if ( storedSecret().isEmpty() ||
                 MD5::hash( s.utf8()  ).hex() == secret().utf8() )
            {
                setState( Succeeded );
            }
            else {
                setState( Failed );
            }
        }

    private:
        UString challenge;
    };

    if ( !d->m ) {
        log( "APOP Command" );

        Utf8Codec c;
        d->m = new Apop( this, c.toUnicode( d->pop->challenge() ) );
        d->m->setState( SaslMechanism::Authenticating );
        d->m->setLogin( c.toUnicode( nextArg() ) );
        d->m->setSecret( nextArg() );
        d->m->execute();
    }

    if ( !d->m->done() )
        return false;

    if ( d->m->state() == SaslMechanism::Succeeded ) {
        d->pop->setUser( d->m->user(), d->m->name() );
        d->cmd = Session;
        return session();
    }
    else {
        d->pop->err( "Authentication failed" );
    }

    return true;
}


/*! Acquires a Session object for the POP server when it enters
    Transaction state.
*/

bool PopCommand::session()
{
    if ( !d->mailbox ) {
        d->mailbox = d->pop->user()->inbox();
        log( "Attempting to start a session on " +
             d->mailbox->name().ascii() );
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
            d->session =
                new PopCommandData::PopSession( d->mailbox, d->pop, ro, this );
            d->session->setPermissions( d->permissions );
            d->pop->setSession( d->session );
        }
    }

    if ( !d->session->initialised() )
        return false;

    if ( !d->map ) {
        d->session->clearUnannounced();
        IntegerSet s( d->session->messages() );
        IntegerSet r;
        d->map = new Map<Message>;
        while ( !s.isEmpty() ) {
            uint uid = s.smallest();
            s.remove( uid );
            Message * m = MessageCache::provide( d->mailbox, uid );
            if ( !m->databaseId() )
                r.add( uid );
            d->map->insert( uid, m );
        }
        if ( !r.isEmpty() ) {
            d->findIds = new Query( "select message, uid "
                                    "from mailbox_messages "
                                    "where mailbox=$1 and uid=any($2)",
                                    this );
            d->findIds->bind( 1, d->mailbox->id() );
            d->findIds->bind( 2, r );
            d->findIds->execute();
        }
    }
    if ( d->findIds && !d->findIds->done() )
        return false;
    while ( d->findIds && d->findIds->hasResults() ) {
        Row * r = d->findIds->nextRow();
        Message * m = d->map->find( r->getInt( "uid" ) );
        if ( m )
            m->setDatabaseId( r->getInt( "message" ) );
    }

    d->session->clearUnannounced();
    d->pop->setMessageMap( d->map );
    d->pop->setState( POP::Transaction );
    d->pop->ok( "Done" );
    return true;
}


/*! Handles the guts of the STAT/LIST data acquisition. */

bool PopCommand::fetch822Size()
{
    ::List<Message> * l = new ::List<Message>;

    uint n = d->set.count();
    while ( n >= 1 ) {
        uint uid = d->set.value( n );
        Message * m = d->pop->message( uid );
        if ( m && !m->hasTrivia() )
            l->prepend( m );
        n--;
    }

    if ( l->isEmpty() )
        return true;

    if ( !d->sentFetch ) {
        d->sentFetch = true;
        Fetcher * mtf = new Fetcher( l, this, 0 );
        mtf->fetch( Fetcher::Trivia );
        mtf->execute();
    }

    return false;
}


/*! Handles the STAT command. */

bool PopCommand::stat()
{
    ::Session * s = d->pop->session();

    if ( !d->started ) {
        log( "STAT command" );
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
        Message * m = d->pop->message( s->uid( n ) );
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
            EString arg = *d->args->first();
            uint msn = arg.number( &ok );
            if ( !ok || msn < 1 || msn > s->count() ) {
                d->pop->err( "Bad message number" );
                return true;
            }
            d->set.add( s->uid( msn ) );
        }
        log( "LIST command (" + d->set.set() + ")" );
    }

    if ( !fetch822Size() )
        return false;

    if ( d->args->count() == 1 ) {
        uint uid = d->set.smallest();
        Message * m = d->pop->message( uid );

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
            Message * m = d->pop->message( uid );
            if ( m )
                d->pop->enqueue( fn( s->msn( uid ) ) + " " +
                                 fn( m->rfc822Size() ) + "\r\n" );
            i++;
        }
        d->pop->enqueue( ".\r\n" );
    }
    return true;
}


/*! Handles both the RETR (if \a lines is false) and TOP (if \a lines
    is true) commands.
*/

bool PopCommand::retr( bool lines )
{
    ::Session * s = d->pop->session();

    if ( !d->started ) {
        bool ok;
        uint msn = nextArg().number( &ok );
        if ( ok )
            log( "RETR command (" + fn( s->uid( msn ) ) + ")" );
        else
            log( "RETR command" );
        if ( !ok || msn < 1 || msn > s->count() ) {
            log( "Bad message number "
             +fn(s->uid(msn))+" "+fn(msn)+"<"+fn(s->count()),
             Log::Significant);
            d->pop->err( "Bad message number" );
            return true;
        }

        if ( lines ) {
            d->n = nextArg().number( &ok );
            if ( !ok ) {
                log( "Bad line count "+fn(d->n), Log::Significant);
                d->pop->err( "Bad line count" );
                return true;
            }
        }

        d->message = d->pop->message( s->uid( msn ) );
        if ( !d->message ) {
            log( "No such message "+fn(s->uid(msn))+" "+fn(msn),
             Log::Significant);
            d->pop->err( "No such message" );
            return true;
        }

        d->started = true;
        Fetcher * f = new Fetcher( d->message, this );
        if ( !d->message->hasBodies() )
            f->fetch( Fetcher::Body );
        if ( !d->message->hasHeaders() )
            f->fetch( Fetcher::OtherHeader );
        if ( !d->message->hasAddresses() )
            f->fetch( Fetcher::Addresses );
        f->execute();
    }

    if ( !( d->message->hasBodies() &&
            d->message->hasHeaders() &&
            d->message->hasAddresses() ) )
        return false;

    if ( d->message->rfc822Size() > 2 )
        d->pop->ok( "Done" );
    else {
        log( "Aborting due to overlapping session", Log::Significant );
        d->pop->abort( "Overlapping sessions" );
        return true;
    }

    Buffer * b = new Buffer;
    b->append( d->message->rfc822( true ) ); // XXX always downgrades

    int ln = d->n;
    bool header = true;
    int lnhead = 0;
    int lnbody = 0;
    int msize = b->size();

    EString * t;
    while ( ( t = b->removeLine() ) != 0 ) {
        if ( header && t->isEmpty() )
            header = false;

        if ( !header && lines && ln-- < 0 )
            break;

        if ( header )
            lnhead++;
        else
            lnbody++;

        if ( t->startsWith( "." ) )
            d->pop->enqueue( "." );
        d->pop->enqueue( *t );
        d->pop->enqueue( "\r\n" );
    }

    EString st = b->string( b->size() );
    if ( !st.isEmpty() && !( !header && lines && ln-- < 0 ) ) {
        if ( st.startsWith( "." ) )
            d->pop->enqueue( "." );
        d->pop->enqueue( st );
        d->pop->enqueue( "\r\n" );
    }

    d->pop->enqueue( ".\r\n" );

    if( !lines )
        log( "Retrieved "
         + fn( lnhead ) + ":" + fn( lnbody ) + "/" + fn( msize )
         + " " + d->message->header()->messageId().forlog(),
         Log::Significant );
    return true;
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
    ::Session * s = d->pop->session();

    bool ok;
    uint msn = nextArg().number( &ok );
    uint uid = 0;
    if ( ok ) {
        uid = s->uid( msn );
        log( "DELE command (" + fn( uid ) + ")" );
    }
    else {
        log( "DELE command" );
    }
    if ( s->readOnly() ) {
        d->pop->err( "Invalid message number" );
    }
    else if ( uid ) {
        d->pop->markForDeletion( uid );
        d->pop->ok( "Done" );
    }
    else {
        d->pop->err( "Invalid message number" );
    }
    return true;
}


/*! Handles the UIDL command. */

bool PopCommand::uidl()
{
    ::Session * s = d->pop->session();

    if ( d->args->count() == 1 ) {
        bool ok;
        uint msn = nextArg().number( &ok );
        if ( !ok || msn < 1 || msn > s->count() ) {
            d->pop->err( "Bad message number" );
            return true;
        }
        uint uid = s->uid( msn );
        log( "UIDL command (" + fn( uid ) + ")" );
        d->pop->ok( fn( msn ) + " " + fn( s->mailbox()->uidvalidity() ) +
                    fn( uid ) );
    }
    else {
        log( "UIDL command" );
        uint msn = 1;

        d->pop->ok( "Done" );
        while ( msn <= s->count() ) {
            uint uid = s->uid( msn );
            d->pop->enqueue( fn( msn ) + " " +
                             fn( s->mailbox()->uidvalidity() ) + "/" +
                             fn( uid ) + "\r\n" );
            msn++;
        }
        d->pop->enqueue( ".\r\n" );
    }

    return true;
}


/*! This function returns the next argument supplied by the client for
    this command, or an empty string if there are no more arguments.
    (Should we assume that nextArg will never be called more times
    than there are arguments? The POP parser does enforce this.)
*/

EString PopCommand::nextArg()
{
    if ( d->args && !d->args->isEmpty() )
        return *d->args->take( d->args->first() );
    return "";
}
