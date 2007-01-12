// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "managesievecommand.h"

#include "tls.h"
#include "user.h"
#include "query.h"
#include "buffer.h"
#include "mechanism.h"
#include "stringlist.h"
#include "sievescript.h"
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


/*! \class ManageSieveCommand managesievecommand.h
    This class represents a single ManageSieve command. It is analogous to a
    POP Command. Almost identical, in fact.
*/


/*! Creates a new ManageSieveCommand object representing the command
    \a cmd with arguments \a args for the ManageSieve server \a sieve.
*/

ManageSieveCommand::ManageSieveCommand( ManageSieve * sieve,
                                        Command cmd, const String & args )
    : d( new ManageSieveCommandData )
{
    d->sieve = sieve;
    d->cmd = cmd;
    d->arg = args;
}


/*! Returns true if this ManageSieveCommand has finished executing, and false if
    execute() hasn't been called, or if it has work left to do.
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
    bool ok = true;
    switch ( d->cmd ) {
    case Logout:
        log( "Received LOGOUT command", Log::Debug );
        d->sieve->Connection::setState( Connection::Closing );
        break;

    case Capability:
        end();
        if ( d->no.isEmpty() )
            d->sieve->capabilities();
        break;

    case StartTls:
        ok = startTls();
        break;

    case Authenticate:
        ok = authenticate();
        break;

    case HaveSpace:
        ok = haveSpace();
        break;

    case PutScript:
        ok = putScript();
        break;

    case ListScripts:
        ok = listScripts();
        break;

    case SetActive:
        ok = setActive();
        break;

    case GetScript:
        ok = getScript();
        break;

    case DeleteScript:
        ok = deleteScript();
        break;

    case Unknown:
        no( "Unknown command" );
        break;
    }

    if ( d->query && d->query->failed() && d->no.isEmpty() )
        no( "Database failed: " + d->query->error() );
    else if ( d->t && d->t->failed() && d->no.isEmpty() )
        no( "Database failed: " + d->t->error() ); // XXX need to rollback?

    if ( !d->no.isEmpty() )
        ok = true;

    if ( !ok )
        return;

    d->done = true;
    if ( d->no.isEmpty() ) {
        d->sieve->enqueue( "OK\r\n" );
    }
    else {
        d->sieve->enqueue( "NO " );
        d->sieve->enqueue( encoded( d->no ) );
        d->sieve->enqueue( "\r\n" );
    };
    d->sieve->write();
    d->sieve->runCommands();
}


/*! Handles the STARTTLS command. */

bool ManageSieveCommand::startTls()
{
    if ( d->sieve->hasTls() ) {
        no( "STARTTLS once = good. STARTTLS twice = bad." );
        return true;
    }

    if ( !d->tlsServer ) {
        end();
        if ( !d->no.isEmpty() )
            return true;
        d->tlsServer = new TlsServer( this, d->sieve->peer(), "ManageSieve" );
        d->sieve->setReserved( true );
    }

    if ( !d->tlsServer->done() )
        return false;

    d->sieve->setReserved( false );
    d->sieve->write();
    d->sieve->startTls( d->tlsServer );

    // here's how.
    d->sieve->capabilities();

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

        whitespace();

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

        end();
        if ( !d->no.isEmpty() )
            return true;
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
        d->sieve->setUser( d->m->user() );
        d->sieve->setState( ManageSieve::Authorised );
    }
    else if ( d->m->state() == SaslMechanism::Terminated ) {
        no( "Authentication terminated" );
    }
    else {
        no( "Authentication failed" );
    }
    d->sieve->setReader( 0 );

    return true;
}


/*! Handles the HAVESPACE command. Accepts any name and size, then
    reports OK: We don't do hard quotas. */

bool ManageSieveCommand::haveSpace()
{
    (void)string();
    whitespace();
    (void)number();
    end();
    return true;
}


/*! Handles the PUTSCRIPT command. */

bool ManageSieveCommand::putScript()
{
    if ( !d->query ) {
        String name = string();
        whitespace();
        SieveScript script;
        script.parse( string() );
        end();
        if ( script.isEmpty() ) {
            no( "Script cannot be empty" );
            return true;
        }
        String e = script.parseErrors();
        if ( !e.isEmpty() ) {
            no( e );
            return true;
        }

        // push the script into the database. we need to either update
        // a table row or insert a new one. ManageSieveCommand doesn't
        // really have the infrastructure to do that. let's hack!
        d->query = new Query( "insert into scripts (owner,name,script,active) "
                              "values($1,$2,$3,false)", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, name );
        d->query->bind( 3, script.source() );
        d->query->allowFailure();
        if ( d->no.isEmpty() )
            d->query->execute();
    }

    if ( !d->query->done() )
        return false;

    if ( d->query->failed() &&
         d->query->string().startsWith( "insert" ) ) {
        // a magnificent hack: If insert into didn't work, we set the
        // state back, change the query string to one that should
        // work, and execute the query again! yaaaaay!
        d->query->setState( Query::Inactive );
        d->query->setString( "update scripts set script=$3 where "
                             "owner=$1 and name=$2" );
        d->query->execute();
        return false;
    }

    return true;
}


/*! Handles the LISTSCRIPTS command. */

bool ManageSieveCommand::listScripts()
{
    if ( !d->query ) {
        end();
        d->query =
            new Query( "select * from scripts where owner=$1", this );
        d->query->bind( 1, d->sieve->user()->id() );
        if ( d->no.isEmpty() )
            d->query->execute();
    }

    while ( d->query->hasResults() ) {
        Row * r = d->query->nextRow();
        String line = encoded( r->getString( "name" ) );
        if ( r->getBoolean( "active" ) )
            line.append( " ACTIVE" );
        d->sieve->send( line );
    }

    if ( !d->query->done() )
        return false;

    return true;
}


/*! Handles the SETACTIVE command. */

bool ManageSieveCommand::setActive()
{
    if ( !d->t ) {
        String name = string();
        end();
        d->t = new Transaction( this );
        d->query =
            new Query( "update scripts set active='f' where owner=$1 and "
                       "active='t' and not name=$2", this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, name );
        d->t->enqueue( d->query );
        d->query =
            new Query( "update scripts set active='t' where owner=$1 and "
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
        end();
        d->query =
            new Query( "select script from scripts where owner=$1 and name=$2",
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
    else if ( !d->query->failed() )
        d->sieve->enqueue( encoded( r->getString( "script" ) ) + "\r\n" );

    return true;
}


/*! Handles the DELETESCRIPT command. */

bool ManageSieveCommand::deleteScript()
{
    if ( !d->t ) {
        String name = string();
        end();
        d->t = new Transaction( this );
        // select first, so the no() calls below work
        d->query =
            new Query( "select active from scripts "
                       "where owner=$1 and name=$2",
                       this );
        d->query->bind( 1, d->sieve->user()->id() );
        d->query->bind( 2, name );
        d->t->enqueue( d->query );
        // then delete
        Query * q = new Query( "delete from scripts where owner=$1 and "
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
        d->pos = i;
    }
    else if ( d->arg[d->pos] == '{' ) {
        uint pos = d->pos;
        d->pos++;
        uint len = number();
        if ( d->arg.mid( d->pos, 4 ) != "+}\r\n" )
            no( "Could not parse literal at position " + fn( pos ) + ": " +
                d->arg.mid( pos, d->pos + 4 - pos ) );
        d->pos += 4;
        r = d->arg.mid( d->pos, len );
        d->pos += len;
    }
    else {
        no( "Could not parse string at position " + fn( d->pos ) + ": " +
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
        no( "Could not find a number at at position " + fn( d->pos ) + ": " +
            d->arg.mid( d->pos, 10 ) );
    bool ok = true;
    uint n = d->arg.mid( d->pos, i-d->pos ).number( &ok );
    if ( !ok )
        no( "Could not parse the number at position " + fn( d->pos ) + ": " +
            d->arg.mid( d->pos, i-d->pos ) );
    d->pos = i;
    return n;
}


/*! Skips whitespace in the argument list. Should perhaps report an
    error if there isn't any? Let's keep it as it is, though.
*/

void ManageSieveCommand::whitespace()
{
    while ( d->arg[d->pos] == ' ' )
        d->pos++;
}


/*! Verifies that parsing has reached the end of the argument list,
    and logs an error else.
*/

void ManageSieveCommand::end()
{
    whitespace();
    if ( d->pos >= d->arg.length() )
        return;
    no( "Garbage at end of argument list (pos " + fn( d->pos ) + "): " +
        d->arg.mid( d->pos, 20 ) );
}


/*! Records that this command is to be rejected, optionally with \a
    message.
*/

void ManageSieveCommand::no( const String & message )
{
    if ( d->no.isEmpty() )
        d->no = message;
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


