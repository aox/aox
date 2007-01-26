// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpcommand.h"

#include "smtphelo.h"
#include "smtpdata.h"
#include "smtpmailrcpt.h"
#include "smtpauth.h"

#include "smtpparser.h"
#include "stringlist.h"
#include "smtp.h"
#include "tls.h"


class SmtpCommandData
    : public Garbage
{
public:
    SmtpCommandData(): responseCode( 0 ), done( false ), smtp( 0 ) {}

    uint responseCode;
    StringList response;
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


/*! Returns the response for this command, including the number and
    trailing CRLF.
*/

String SmtpCommand::response() const
{
    String r;
    String n = fn( d->responseCode );
    StringList::Iterator it( d->response );
    do {
        String l = *it;
        ++it;
        r.append( n );
        if ( !it )
            r.append( " " );
        else
            r.append( "-" );
        r.append( l );
        r.append( "\r\n" );
    } while ( it );
    log( "Sending response '" + r + "'",
         d->responseCode >= 400 ? Log::Info : Log::Debug );
    return r;
}


/*! Returns true if this command has completed with a non-error
    response code, true if it hasn't completed, and false if it has
    completed with an error code.
*/

bool SmtpCommand::ok() const
{
    return d->responseCode < 400;
}


/*! Records that the (three-digit) response code for this command is
    \a r, and that \a s is to be one of the text lines sent. \a s
    should not have a trailing CRLF.

    If \a r is 0, the existing response code is not changed.
*/

void SmtpCommand::respond( uint r, const String & s )
{
    if ( r )
        d->responseCode = r;
    d->response.append( s );
}


void SmtpCommand::execute()
{
    return;
}


/*! Creates an SmtpCommand object to handle \a command within the
    context of \a server. \a server cannot be null.
*/

SmtpCommand * SmtpCommand::create( SMTP * server, const String & command )
{
    SmtpParser * p = new SmtpParser( command );
    String c = p->command();
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
        r->respond( 500, "Unknown command (" + c.upper() + ")" );
    }

    if ( !r->done() && r->d->responseCode < 400 && !p->error().isEmpty() )
        r->respond( 501, p->error() );

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
    server()->reset();
    respond( 250, "State reset" );
    finish();
}

/*! \class SmtpNoop smtpcommand.h
    Handles the NOOP command.
*/

/*! Creates a new NOOP handler for \a s. */

SmtpNoop::SmtpNoop( SMTP * s, SmtpParser * )
    : SmtpCommand( s )
{
    respond( 250, "OK" );
    finish();
}


/*! \class SmtpHelp smtpcommand.h
    Handles the HELP command.
*/

/*! Issues help, except not. \a s is the SMTP server, as usual. */

SmtpHelp::SmtpHelp( SMTP * s, SmtpParser * )
    : SmtpCommand( s )
{
    respond( 250, "See http://aox.org" );
}


/*! \class SmtpStarttls smtpcommand.h
    Handles the STARTTLS command.
*/

/*! Starts TLS negotiation as server for \a s. */

SmtpStarttls::SmtpStarttls( SMTP * s, SmtpParser * )
    : SmtpCommand( s ), tlsServer( 0 )
{
    tlsServer = new TlsServer( this, server()->peer(), "SMTP" );
}


void SmtpStarttls::execute()
{
    if ( server()->hasTls() ) {
        respond( 502, "Already using TLS" );
        finish();
        return;
    }

    if ( !tlsServer->done() )
        return;

    server()->enqueue( "220 Start negotiating TLS now.\r\n" );
    server()->write();
    finish();
    log( "Negotiating TLS", Log::Debug );
    server()->startTls( tlsServer );

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
    respond( 221, "Have a nice day." );
    finish();
    server()->setState( Connection::Closing );
}
