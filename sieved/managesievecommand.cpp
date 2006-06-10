// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "managesievecommand.h"

#include "tls.h"
#include "user.h"
#include "query.h"
#include "buffer.h"
#include "mechanism.h"
#include "stringlist.h"
#include "transaction.h"


class ManageSieveCommandData
    : public Garbage
{
public:
    ManageSieveCommandData()
        : sieve( 0 ), args( 0 ), done( false ),
          tlsServer( 0 ), m( 0 ), r( 0 ),
          user( 0 ), t( 0 ), query( 0 )
    {}

    ManageSieve * sieve;
    ManageSieveCommand::Command cmd;
    StringList * args;

    bool done;

    TlsServer * tlsServer;
    SaslMechanism * m;
    String * r;
    User * user;

    Transaction * t;
    Query * query;
    String s;
};


/*! \class ManageSieveCommand sievecommand.h
    This class represents a single ManageSieve command. It is analogous to a
    POP Command. Almost identical, in fact.
*/


/*! Creates a new ManageSieveCommand object representing the command \a cmd,
    for the ManageSieve server \a sieve.
*/

ManageSieveCommand::ManageSieveCommand( ManageSieve * sieve, Command cmd, StringList * args )
    : d( new ManageSieveCommandData )
{
    d->sieve = sieve;
    d->cmd = cmd;
    d->args = args;
}


/*! Marks this command as having finished execute()-ing. Any responses
    are written to the client, and the ManageSieve server is instructed to move
    on to processing the next command.
*/

void ManageSieveCommand::finish()
{
    d->done = true;
    d->sieve->write();
    d->sieve->runCommands();
}


/*! Returns true if this ManageSieveCommand has finished executing, and false if
    execute() hasn't been called, or if it has work left to do. Once the
    work is done, execute() calls finish() to signal completion.
*/

bool ManageSieveCommand::done()
{
    return d->done;
}


/*! Tries to read a single response line from the client. Upon return,
    d->r points to the response, or is 0 if no response could be read.
*/

void ManageSieveCommand::read()
{
    d->r = d->sieve->readBuffer()->removeLine();
}


void ManageSieveCommand::execute()
{
    switch ( d->cmd ) {
    case Logout:
        log( "Received LOGOUT command", Log::Debug );
        d->sieve->ok( "" );
        d->sieve->Connection::setState( Connection::Closing );
        break;

    case Capability:
        d->sieve->capabilities();
        break;

    case StartTls:
        if ( !startTls() )
            return;
        break;

    case Authenticate:
        if ( !authenticate() )
            return;
        break;

    case HaveSpace:
        if ( !haveSpace() )
            return;
        break;

    case PutScript:
        if ( !putScript() )
            return;
        break;

    case ListScripts:
        if ( !listScripts() )
            return;
        break;

    case SetActive:
        if ( !setActive() )
            return;
        break;

    case GetScript:
        if ( !getScript() )
            return;
        break;

    case DeleteScript:
        if ( !deleteScript() )
            return;
        break;
    }

    finish();
}


/*! Handles the STARTTLS command. */

bool ManageSieveCommand::startTls()
{
    if ( !d->tlsServer ) {
        d->tlsServer = new TlsServer( this, d->sieve->peer(), "ManageSieve" );
        d->sieve->setReserved( true );
    }

    if ( !d->tlsServer->done() )
        return false;

    d->sieve->ok( "Done" );
    d->sieve->setReserved( false );
    d->sieve->write();
    d->sieve->startTls( d->tlsServer );

    // XXX: We're supposed to resend the capability list after the TLS
    // negotiation is complete. How on earth can we do that?

    return true;
}


/*! Handles the AUTHENTICATE command. */

bool ManageSieveCommand::authenticate()
{
    if ( !d->m ) {
        String t = nextArg().lower();
        d->m = SaslMechanism::create( t, this, d->sieve->hasTls() );
        if ( !d->m ) {
            d->sieve->no( "SASL mechanism " + t + " not supported" );
            return true;
        }
        d->sieve->setReader( this );

        String r = nextArg();
        if ( d->m->state() == SaslMechanism::AwaitingInitialResponse ) {
            if ( !r.isEmpty() ) {
                d->m->readResponse( r.de64() );
                if ( !d->m->done() )
                    d->m->execute();
            }
            else {
                d->m->setState( SaslMechanism::IssuingChallenge );
            }
        }
    }

    // This code is essentially a mangled copy of imapd/handlers/authenticate.
    // I'll think about how to avoid the duplication later.
    while ( !d->m->done() &&
            ( d->m->state() == SaslMechanism::IssuingChallenge ||
              d->m->state() == SaslMechanism::AwaitingResponse ) ) {
        if ( d->m->state() == SaslMechanism::IssuingChallenge ) {
            String c = d->m->challenge().e64();

            if ( !d->m->done() ) {
                d->sieve->enqueue( "+ "+ c +"\r\n" );
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
        d->sieve->setReader( 0 );
        d->sieve->setUser( d->m->user() );
        d->sieve->ok( "" );
    }
    else if ( d->m->state() == SaslMechanism::Terminated ) {
        d->sieve->no( "Authentication terminated" );
    }
    else {
        d->sieve->no( "Authentication failed" );
    }

    return true;
}


/*! Handles the HAVESPACE command. */

bool ManageSieveCommand::haveSpace()
{
    // Why support quotas when we can lie through our teeth?
    d->sieve->ok( "" );
    return true;
}


/*! Handles the PUTSCRIPT command. */

bool ManageSieveCommand::putScript()
{
    if ( !d->query ) {
        d->s = nextArg();
        // XXX: Oops, we don't support literals yet.
        d->query =
            new Query( "insert into scripts (owner,name,text) "
                       "values ($1,$2)", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, d->s );
        // XXX: Nor do we bother to check the script for validity.
        d->query->bind( 3, "foobar" );
        d->query->execute();
    }

    if ( !d->query->done() )
        return false;

    if ( d->query->failed() )
        d->sieve->no( "Couldn't store script " + d->s );
    else
        d->sieve->ok( "" );

    return true;
}


/*! Handles the LISTSCRIPTS command. */

bool ManageSieveCommand::listScripts()
{
    if ( !d->query ) {
        d->query =
            new Query( "select * from scripts where user=$1", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->execute();
    }

    while ( d->query->hasResults() ) {
        Row * r = d->query->nextRow();
        String line( "\"" + r->getString( "name" ) + "\"" );
        if ( r->getBoolean( "active" ) )
            line.append( " ACTIVE" );
        d->sieve->send( line );
    }

    if ( !d->query->done() )
        return false;

    if ( d->query->failed() )
        d->sieve->no( "Couldn't fetch script list" );
    else
        d->sieve->ok( "" );

    return true;
}


/*! Handles the SETACTIVE command. */

bool ManageSieveCommand::setActive()
{
    if ( !d->t ) {
        d->s = nextArg();
        d->t = new Transaction( this );
        d->query =
            new Query( "update scripts set active='f' where user=$1", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->t->enqueue( d->query );
        d->query =
            new Query( "update scripts set active='t' where user=$1 and "
                       "name=$2", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, d->s );
        d->t->enqueue( d->query );
        d->t->commit();
    }

    if ( !d->t->done() )
        return false;

    if ( d->t->failed() )
        d->sieve->no( "Couldn't activate script " + d->s );
    else
        d->sieve->ok( "" );

    return true;
}


/*! Handles the GETSCRIPT command. */

bool ManageSieveCommand::getScript()
{
    if ( !d->query ) {
        d->s = nextArg();
        d->query =
            new Query( "select * from scripts where user=$1 and name=$2",
                       this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, d->s );
        d->query->execute();
    }

    if ( !d->query->done() )
        return false;

    Row * r = d->query->nextRow();

    if ( !r || d->query->failed() ) {
        d->sieve->no( "Couldn't get script " + d->s );
    }
    else {
        String text( r->getString( "script" ) );
        // XXX: Oops, we don't have literal support yet.
        d->sieve->ok( "" );
    }

    return true;
}


/*! Handles the DELETESCRIPT command. */

bool ManageSieveCommand::deleteScript()
{
    if ( !d->t ) {
        d->s = nextArg();
        d->t = new Transaction( this );
        d->query =
            new Query( "select from scripts where user=$1 and name=$2",
                       this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, d->s );
        d->t->enqueue( d->query );
        d->t->execute();
    }

    if ( d->query && d->query->done() ) {
        Row * r = d->query->nextRow();
        if ( !r || d->query->failed() ) {
            d->sieve->no( "Can't delete script " + d->s );
        }
        else {
            if ( r->getBoolean( "active" ) ) {
                d->sieve->no( "Can't delete active script " + d->s );
            }
            else {
                d->query =
                    new Query( "delete from scripts where user=$1 and "
                               "name=$2 active='f'", this );
                d->query->bind( 1, d->sieve->user()->id() );
                d->query->bind( 2, d->s );
                d->t->enqueue( d->query );
                d->query = 0;
            }
        }

        d->t->commit();
    }

    if ( !d->t->done() )
        return false;

    if ( d->t->failed() )
        d->sieve->no( "Couldn't delete script " + d->s );
    else
        d->sieve->ok( "Deleted" );

    return true;
}


/*! This function returns the next argument supplied by the client for
    this command, or an empty string if there are no more arguments.
    (Should we assume that nextArg will never be called more times
    than there are arguments? The ManageSieve parser does enforce this.)
*/

String ManageSieveCommand::nextArg()
{
    if ( !d->args )
        return "";
    if ( d->args->isEmpty() )
        return "";
    String s = *d->args->take( d->args->first() );
    if ( s.startsWith( "{" ) ) {
        // XXX so what do we do here?
        while ( true )
            ; // XXX indeed
    }
    else if ( s.isQuoted() ) {
        return s.unquoted();
    }
    return s;
}
