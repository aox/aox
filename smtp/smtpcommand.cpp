// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "smtpcommand.h"

#include "smtphelo.h"
#include "smtpdata.h"
#include "smtpmailrcpt.h"
#include "smtpauth.h"

#include "smtpparser.h"
#include "estringlist.h"
#include "eventloop.h"
#include "scope.h"
#include "smtp.h"


class SmtpCommandData
    : public Garbage
{
public:
    SmtpCommandData()
        : responseCode( 200 ), enhancedCode( 0 ),
          done( false ), smtp( 0 ) {}

    uint responseCode;
    const char * enhancedCode;
    EStringList response;
    bool done;
    SMTP * smtp;
};


/*! \class SmtpCommand smtpcommand.h

    The SmtpCommand models a single SMTP command (including "unknown
    command"). Some of them are subclasses.

    An SmtpCommand must be able to parse its arguments and execute itself.
*/


/*! Constructs an empty command for the server \a s. */

SmtpCommand::SmtpCommand( class SMTP * s )
    : EventHandler(), d( new SmtpCommandData )
{
    setLog( new Log );
    d->smtp = s;
}


/*! Records that this command is finished and tells the SMTP server to
    emit responses and generally get on with life. The response may be
    sent, and SMTP::execute() should not call execute() again.
*/

void SmtpCommand::finish()
{
    d->done = true;
    d->smtp->execute();
}


/*! Returns true if this command has finished its work, and false
    otherwise.
*/

bool SmtpCommand::done() const
{
    return d->done;
}




/*! Outputs the response for this command, including the number and
    trailing CRLF.
*/

void SmtpCommand::emitResponses()
{
    if ( !d->responseCode )
        return;

    Scope x( log() );
    EString r;
    EString n = fn( d->responseCode );
    EStringList::Iterator it( d->response );
    uint crlf = 0;
    while ( it ) {
        EString l = *it;
        ++it;
        r.append( n );
        if ( !it )
            r.append( " " );
        else
            r.append( "-" );
        if ( d->enhancedCode ) {
            r.append( d->enhancedCode );
            r.append( " " );
        }
        r.append( l );
        if ( !crlf )
            crlf = r.length();
        r.append( "\r\n" );
    }
    EString l = r.mid( 0, crlf );
    if ( d->response.count() > 1 )
        l.append( " (+" + fn( d->response.count() - 1 ) + " more lines)" );
    log( "Response: " + l,
         d->responseCode >= 400 ? Log::Info : Log::Debug );
    server()->enqueue( r );
    d->responseCode = 0;
    d->response.clear();
}


/*! Returns true if this command has completed with a non-error
    response code, true if it hasn't completed, and false if it has
    completed with an error code. Toggles to true again after
    emitResponses().
*/

bool SmtpCommand::ok() const
{
    return d->responseCode < 400;
}


/*! Records that the (three-digit) response code for this command is
    \a r, that \a enh is either null (the default) or an enhanced
    status code as defined in RFC 2034, and that \a s is to be one of
    the text lines sent. \a s should not have a trailing CRLF.

    If \a r is 0, the existing response code is not changed.
    Similarly, if \a enh is null, the existing enhanced respons code
    is not changed.
*/

void SmtpCommand::respond( uint r, const EString & s, const char * enh )
{
    Scope x( log() );
    if ( r )
        d->responseCode = r;
    if ( enh )
        d->enhancedCode = enh;
    d->response.append( s );
}


void SmtpCommand::execute()
{
    return;
}


/*! Creates an SmtpCommand object to handle \a command within the
    context of \a server. \a server cannot be null.

    This function rejects commands issued while the server is shutting
    down. If a command passes this hurdle, it will be executed to
    completion, even if the server starts shutting down. This implies
    that if we're receiving a message body when the shutdown command
    is given, we will receive and inject the message, as RFC 1047
    suggests.
*/

SmtpCommand * SmtpCommand::create( SMTP * server, const EString & command )
{
    SmtpParser * p = new SmtpParser( command );
    EString c = p->command();
    SmtpCommand * r;

    if ( c == "helo" ) {
        r = new SmtpHelo( server, p, SmtpHelo::Helo );
    }
    else if ( c == "ehlo" ) {
        r = new SmtpHelo( server, p, SmtpHelo::Ehlo );
    }
    else if ( c == "lhlo" ) {
        r = new SmtpHelo( server, p, SmtpHelo::Lhlo );
    }
    else if ( c == "rset" ) {
        r = new SmtpRset( server, p );
    }
    else if ( c == "mail from" ) {
        r = new SmtpMailFrom( server, p );
    }
    else if ( c == "rcpt to" ) {
        r = new SmtpRcptTo( server, p );
    }
    else if ( c == "data" ) {
        r = new SmtpData( server, p );
    }
    else if ( c == "bdat" ) {
        r = new SmtpBdat( server, p );
    }
    else if ( c == "burl" ) {
        r = new SmtpBurl( server, p );
    }
    else if ( c == "noop" ) {
        r = new SmtpNoop( server, p );
    }
    else if ( c == "help" ) {
        r = new SmtpHelp( server, p );
    }
    else if ( c == "starttls" ) {
        r = new SmtpStarttls( server, p );
    }
    else if ( c == "quit" ) {
        r = new SmtpQuit( server, p );
    }
    else if ( c == "auth" ) {
        r = new SmtpAuth( server, p );
    }
    else {
        r = new SmtpCommand( server );
        r->respond( 500, "Unknown command (" + c.upper() + ")", "5.5.1" );
    }

    Scope x( r->log() );
    r->log( "Command: " + command.simplified(), Log::Debug );

    if ( !r->done() && r->d->responseCode < 400 && !p->error().isEmpty() )
        r->respond( 501, p->error(), "5.5.2" );

    if ( !r->done() && EventLoop::global()->inShutdown() )
        r->respond( 421, "Server shutdown", "4.3.2" );

    if ( !r->d->done && r->d->responseCode >= 400 )
        r->d->done = true;

    return r;
}


/*! Returns a pointer to the SMTP server for this command. */

SMTP * SmtpCommand::server() const
{
    return d->smtp;
}


/*! \class SmtpRset smtpcommand.h
    Handles the RSET command.
*/

/*! Creates a new SmtpRset handler for \a s. */

SmtpRset::SmtpRset( SMTP * s, SmtpParser * )
    : SmtpCommand( s )
{
}


void SmtpRset::execute()
{
    if ( !server()->isFirstCommand( this ) )
        return;
    server()->reset();
    respond( 250, "State reset", "2.0.0" );
    finish();
}

/*! \class SmtpNoop smtpcommand.h
    Handles the NOOP command.
*/

/*! Creates a new NOOP handler for \a s. */

SmtpNoop::SmtpNoop( SMTP * s, SmtpParser * )
    : SmtpCommand( s )
{
    respond( 250, "OK", "2.0.0" );
    finish();
}


/*! \class SmtpHelp smtpcommand.h
    Handles the HELP command.
*/

/*! Issues help, except not. \a s is the SMTP server, as usual. */

SmtpHelp::SmtpHelp( SMTP * s, SmtpParser * )
    : SmtpCommand( s )
{
    respond( 250, "See http://aox.org", "2.0.0" );
    finish();
}


/*! \class SmtpStarttls smtpcommand.h
    Handles the STARTTLS command.
*/

/*! Starts TLS negotiation as server for \a s. */

SmtpStarttls::SmtpStarttls( SMTP * s, SmtpParser * )
    : SmtpCommand( s ), startedTls( false ), tlsServer( 0 )
{
    Scope x( log() );
}


void SmtpStarttls::execute()
{
    if ( startedTls ) {
        respond( 502, "Already using TLS", "5.5.1" );
        finish();
        return;
    }

    if ( !server()->isFirstCommand( this ) )
        return;

    startedTls = true;
    log( "Negotiating TLS", Log::Debug );
    server()->enqueue( "220 2.0.0 Start negotiating TLS now.\r\n" );
    server()->startTls( tlsServer );
    finish();
}


/*! \class SmtpQuit smtpcommand.h
    Handles the QUIT command.
*/

/*! Creates a new SmtpQuit handler for \a s. */

SmtpQuit::SmtpQuit( SMTP * s, SmtpParser * )
    : SmtpCommand( s )
{
    // nothing
}


void SmtpQuit::execute()
{
    if ( !server()->isFirstCommand( this ) )
        return;
    respond( 221, "Have a nice day.", "2.0.0" );
    finish();
    server()->setState( Connection::Closing );
}
