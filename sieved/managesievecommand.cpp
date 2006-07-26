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
        : sieve( 0 ), pos( 0 ), done( false ),
          tlsServer( 0 ), m( 0 ), r( 0 ),
          user( 0 ), t( 0 ), query( 0 )
    {}

    ManageSieve * sieve;
    ManageSieveCommand::Command cmd;
    String arg;
    uint pos;

    bool done;

    TlsServer * tlsServer;
    SaslMechanism * m;
    String * r;
    User * user;

    Transaction * t;
    Query * query;
    String no;
};


/*! \class ManageSieveCommand sievecommand.h
    This class represents a single ManageSieve command. It is analogous to a
    POP Command. Almost identical, in fact.
*/


/*! Creates a new ManageSieveCommand object representing the command \a cmd,
    for the ManageSieve server \a sieve.
*/

ManageSieveCommand::ManageSieveCommand( ManageSieve * sieve,
                                        Command cmd, const String & args )
    : d( new ManageSieveCommandData )
{
    d->sieve = sieve;
    d->cmd = cmd;
    d->arg = args;
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

    case Unknown:
        d->sieve->no( "Unknown command" );
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
        String t = string().lower();
        d->m = SaslMechanism::create( t, this, d->sieve->hasTls() );
        if ( !d->m ) {
            no( "SASL mechanism " + t + " not supported" );
            return true;
        }
        d->sieve->setReader( this );

        String r = string();
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
    }
    else if ( d->m->state() == SaslMechanism::Terminated ) {
        no( "Authentication terminated" );
    }
    else {
        no( "Authentication failed" );
    }

    return true;
}


/*! Handles the HAVESPACE command. */

bool ManageSieveCommand::haveSpace()
{
    // Why support quotas when we can lie through our teeth?
    return true;
}


/*! Handles the PUTSCRIPT command. */

bool ManageSieveCommand::putScript()
{
    if ( !d->query ) {
        d->query =
            new Query( "insert into scripts (owner,name,text) "
                       "values ($1,$2,$3)", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, string() );
        d->query->bind( 3, string() );
        // XXX: Nor do we bother to check the script for validity.
        if ( d->no.isEmpty() )
            d->query->execute();
    }

    if ( !d->query->done() )
        return false;

    if ( d->query->failed() )
        no( "Couldn't store script: " + d->query->error() );

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
        String line = r->getString( "name" ).quoted();
        if ( r->getBoolean( "active" ) )
            line.append( " ACTIVE" );
        d->sieve->send( line );
    }

    if ( !d->query->done() )
        return false;

    if ( d->query->failed() )
        no( "Couldn't fetch script list: " + d->query->error() );

    return true;
}


/*! Handles the SETACTIVE command. */

bool ManageSieveCommand::setActive()
{
    if ( !d->t ) {
        String name = string();
        d->t = new Transaction( this );
        d->query =
            new Query( "update scripts set active='f' where user=$1 and "
                       "active='t' and not name=$2", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, name );
        d->t->enqueue( d->query );
        d->query =
            new Query( "update scripts set active='t' where user=$1 and "
                       "name=$2 and active='f'", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, name );
        d->t->enqueue( d->query );
        if ( d->no.isEmpty() )
            d->t->commit();
    }

    if ( !d->t->done() )
        return false;

    if ( d->t->failed() )
        no( "Couldn't activate script: " + d->t->error() );

    return true;
}


/*! Handles the GETSCRIPT command. */

bool ManageSieveCommand::getScript()
{
    if ( !d->query ) {
        d->query =
            new Query( "select script from scripts where user=$1 and name=$2",
                       this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, string() );
        if ( d->no.isEmpty() )
            d->query->execute();
    }

    if ( !d->query->done() )
        return false;

    Row * r = d->query->nextRow();

    if ( !r )
        no( "No such script" );
    else if ( d->query->failed() )
        no( "Couldn't get script: " + d->query->error() );
    else
        d->sieve->enqueue( encoded( r->getString( "script" ) ) + "\r\n" );

    return true;
}


/*! Handles the DELETESCRIPT command. */

bool ManageSieveCommand::deleteScript()
{
    if ( !d->t ) {
        String name = string();
        d->t = new Transaction( this );
        // select first, so the no() calls below work
        d->query =
            new Query( "select active from scripts "
                       "where user=$1 and name=$2",
                       this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, name );
        d->t->enqueue( d->query );
        // then delete
        Query * q = new Query( "delete from scripts where user=$1 and "
                               "name=$2 and active='f'", this );
        q->bind( 1, d->sieve->user()->id() );
        q->bind( 2, name );
        d->t->enqueue( q );
        if ( d->no.isEmpty() )
            d->t->commit();
    }

    if ( d->query && d->query->done() ) {
        Row * r = d->query->nextRow();
        if ( !r )
            no( "No such script" );
        else if ( r->getBoolean( "active" ) )
            no( "Can't delete active script" );
    }

    if ( !d->t->done() )
        return false;

    if ( d->t->failed() )
        d->sieve->no( "Couldn't delete script: " + d->t->error() );

    return true;
}


/*! Returns the next argument from the client, which must be a string,
    or sends a NO.
*/

String ManageSieveCommand::string()
{
    String r;
    if ( d->arg[d->pos] == '"' ) {
        uint i = d->pos + 1;
        while ( i < d->arg.length() && d->arg[i] != '"' ) {
            if ( d->arg[i] == '\\' )
                i++;
            r.append( d->arg[i] );
            i++;
        }
        if ( d->arg[i] == '"' )
            i++;
        while ( d->arg[i] == ' ' )
            i++;
        d->pos = i;
    }
    else if ( d->arg[d->pos] == '{' ) {
        uint pos = d->pos;
        d->pos++;
        uint len = number();
        if ( d->arg.mid( d->pos, 4 ) != "+}\r\n" )
            no( "Could not parse literal at " + fn( pos ) + ": " +
                d->arg.mid( pos, d->pos + 4 - pos ) );
        d->pos += 4;
        r = d->arg.mid( d->pos, len );
        d->pos += len;
    }
    else {
        no( "Could not parse string at " + fn( d->pos ) + ": " +
            d->arg.mid( d->pos, 10 ) );
    }

    return r;
}


/*! Returns the next number from the client, or sends a NO if there
    isn't a number (in the 32-bit range).
*/

uint ManageSieveCommand::number()
{
    uint i = d->pos;
    while ( d->arg[i] >= '0' && d->arg[i] <= '9' )
        i++;
    if ( i == d->pos )
        no( "Could not find a number at at " + fn( d->pos ) + ": " +
            d->arg.mid( d->pos, 10 ) );
    bool ok = true;
    uint n = d->arg.mid( d->pos, i-d->pos ).number( &ok );
    if ( !ok )
        no( "Could not parse the number at " + fn( d->pos ) + ": " +
            d->arg.mid( d->pos, i-d->pos ) );
    d->pos = i;
    return n;
}


/*! Records that this command is to be rejected, optionally with \a
    message.
*/

void ManageSieveCommand::no( const String & message )
{
    if ( d->no.isEmpty() )
        d->no = message;
}


/*! Returns the argument to no(), or an empty string if no() hasn't
    been called.
*/

String ManageSieveCommand::errorMessage()
{
    return d->no;
}


/*! Returns \a input encoded either as a managesieve quoted or literal
    string. Quoted is preferred, if possible.
*/

String ManageSieveCommand::encoded( const String & input )
{
    bool q = true;
    if ( input.length() > 1024 )
        q = false;
    uint i = 0;
    while ( q && i < input.length() ) {
        if ( input[i] == 0 || input[i] == 13 || input[i] == 10 )
            q = false;
        i++;
    }

    if ( q )
        return input.quoted();

    String r( "{" );
    r.append( String::fromNumber( input.length() ) );
    r.append( "+}\r\n" );
    r.append( input );
    return r;
}
