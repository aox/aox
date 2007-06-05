// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtp.h"

#include "smtpmailrcpt.h"
#include "smtpcommand.h"
#include "transaction.h"
#include "eventloop.h"
#include "mailbox.h"
#include "buffer.h"
#include "sieve.h"
#include "user.h"
#include "tls.h"


class SMTPData
    : public Garbage
{
public:
    SMTPData():
        executing( false ), executeAgain( false ),
        inputState( SMTP::Command ),
        dialect( SMTP::Smtp ),
        sieve( 0 ), user( 0 ),
        recipients( new List<SmtpRcptTo> ){}

    bool executing;
    bool executeAgain;
    SMTP::InputState inputState;
    SMTP::Dialect dialect;
    Sieve * sieve;
    List<SmtpCommand> commands;
    String heloName;
    User * user;
    List<SmtpRcptTo> * recipients;
    String body;
};


class SubmissionMailboxCreator
    : public EventHandler
{
public:
    SubmissionMailboxCreator() {
        Mailbox * m = Mailbox::obtain( "/archiveopteryx/spool", true );
        Transaction * t = new Transaction( this );
        Query * q = m->create( t, 0 );
        if ( q )
            t->commit();
        else
            t->rollback();
    }

    void execute() {
        log( "Created spool mailbox for outgoing mail: "
             "/archiveopteryx/spool" );
    }
};



/*! \class SMTP smtp.h
    The SMTP class implements a basic SMTP server.

    This is not a classic MTA. It implements all that's needed to
    deliver to local users, and for local users to submit messages to
    others. Nothing more.

    This class implements SMTP as specified by RFC 2821, with the
    extensions specified by RFC 1651 (EHLO), RFC 1652 (8BITMIME), RFC
    2487 (STARTTLS), RFC 2554 (AUTH), RFC 3030 (BINARYMIME and
    CHUNKING) and RFC 4468 (BURL).
*/

/*! \class LMTP smtp.h
    This subclass of SMTP implements LMTP (RFC 2033).
*/

/*! \class SMTPSubmit smtp.h
    This subclass of SMTP implements SMTP submission (RFC 4409).
*/

/*!  Constructs an (E)SMTP server for socket \a s, speaking \a dialect. */

SMTP::SMTP( int s, Dialect dialect )
    : Connection( s, Connection::SmtpServer ), d( new SMTPData )
{
    d->dialect = dialect;
    switch( dialect ) {
    case Smtp:
        enqueue( "220 ESMTP " );
        break;
    case Lmtp:
        enqueue( "220 LMTP " );
        break;
    case Submit:
        enqueue( "220 SMTP Submission " );
        break;
    }
    enqueue( Configuration::hostname() );
    enqueue( "\r\n" );
    setTimeoutAfter( 1800 );
    EventLoop::global()->addConnection( this );
    (void)new SubmissionMailboxCreator;
}


/*! Constructs an LMTP server of socket \a s. */

LMTP::LMTP( int s )
    : SMTP( s, SMTP::Lmtp )
{
}


/*!  Constructs a SMTP/submit server (see RFC 4409) for socket \a s. */

SMTPSubmit::SMTPSubmit( int s )
    : SMTP( s, SMTP::Submit )
{
}


void SMTP::react( Event e )
{
    switch ( e ) {
    case Read:
        setTimeoutAfter( 1800 );
        parse();
        break;

    case Timeout:
        log( "Idle timeout" );
        enqueue( "421 Tempus fugit\r\n" );
        Connection::setState( Closing );
        break;

    case Connect:
    case Error:
    case Close:
        break;

    case Shutdown:
        enqueue( "421 Server shutdown\r\n" );
        break;
    }
    execute();
}


/*! Parses the SMTP/LMTP input stream.
*/

void SMTP::parse()
{
    Buffer * r = readBuffer();
    bool progress = true;
    while ( progress && Connection::state() == Connected ) {
        uint n = r->size();
        if ( inputState() == Command )
            parseCommand();
        else
            d->commands.last()->execute();
        if ( r->size() >= n )
            progress = false;
    }
}


/*! Reads a single SMTP/LMTP/Submit command from the client and
    creates an execution object for it.

    Line length is limited to 4096: RFC 2821 section 4.5.3 says 512 is
    acceptable and various SMTP extensions may increase it. RFC 2822
    declares that line lengths should be limited to 998 characters.
*/

void SMTP::parseCommand()
{
    Buffer * r = readBuffer();
    String * line = r->removeLine( 4096 );
    if ( !line && r->size() > 4096 ) {
        log( "Connection closed due to overlong line", Log::Error );
        enqueue( "500 Line too long (legal maximum is 998 bytes)\r\n" );
        Connection::setState( Closing );
        return;
    }
    if ( !line )
        return;
    
    log( "Received: '" + line->simplified() + "'", Log::Debug );
    d->commands.append( SmtpCommand::create( this, *line ) );
}


/*! Runs all outstanding commands. When the oldest command is done,
    execute() removes it from the list and sends its responses to the
    client.
*/

void SMTP::execute()
{
    // make sure we don't call execute() recursively.
    if ( d->executing ) {
        d->executeAgain = true;
        return;
    }
    d->executing = true;
    d->executeAgain = true;
    
    // run each command, and do the whole loop again if execute() is
    // called recursively meanwhile.
    while ( d->executeAgain ) {
        d->executeAgain = false;
        List<SmtpCommand>::Iterator i( d->commands );
        while ( i ) {
            SmtpCommand * c = i;
            ++i;
            if ( !c->done() )
                c->execute();
        }

        // see if any old commands may be retired
        i = d->commands.first();
        while ( i && i->done() ) {
            d->executeAgain = true;
            enqueue( i->response() );
            d->commands.take( i );
        }
    }

    // allow execute() to be called again
    d->executing = false;
}


/*! Returns the dialect used, ie. SMTP, LMTP or SMTP/Submit. */

SMTP::Dialect SMTP::dialect() const
{
    return d->dialect;
}


/*! Records that the client claims to be called \a name. \a name isn't
    used for anything, just logged and recorded in any received fields
    generated.
*/

void SMTP::setHeloName( const String & name )
{
    d->heloName = name;
}


/*! Returns the recorded HELO name, as recorded by setHeloName(). The
    initial value is an empty string.
*/

String SMTP::heloName() const
{
    return d->heloName;
}


/*! Resets most transaction variables, so a new mail from/rcpt to/data
    cycle can begin. Leaves the heloName() untouched, since some
    clients do not resent helo/ehlo/lhlo.
*/

void SMTP::reset()
{
    d->sieve = 0;
    d->recipients = new List<SmtpRcptTo>;
    d->body.truncate();
}


/*! Returns a pointer to the Sieve that manages local delivery for
    this SMTP server.

*/

class Sieve * SMTP::sieve() const
{
    if ( !d->sieve )
        d->sieve = new Sieve;
    return d->sieve;
}


/*! Returns a pointer to the authenticated user, or a null pointer if
    the connection is unauthenticated.
*/

class User * SMTP::user() const
{
    return d->user;
}


/*! Sets this server's authenticated user to \a user. */

void SMTP::authenticated( User * user )
{
    d->user = user;
}


/*! Returns the current input state, which is Command initially. */

SMTP::InputState SMTP::inputState() const
{
    return d->inputState;
}


/*! Notifies this SMTP server that its input state is now \a s. If the
    state is anything other than Command, the SMTP server calls the
    last SmtpCommand every time there's more input. Eventually, the
    SmtpCommand has to call setInputState( Command ) again.

*/

void SMTP::setInputState( InputState s )
{
    d->inputState = s;
}


/*! Notifies this SMTP server that \a r is a valid rcpt to
    command. SMTP records that so the LMTP SmtpData command can use
    the list later.
*/

void SMTP::addRecipient( SmtpRcptTo * r )
{
    d->recipients->append( r );
}


/*! Returns a list of all valid SmtpRcptTo commands. This is never a
    null pointer, but may be an empty list.
*/

List<SmtpRcptTo> * SMTP::rcptTo() const
{
    return d->recipients;
}


/*! Records \a b for later recall. reset() clears this. */

void SMTP::setBody( const String & b )
{
    d->body = b;
}


/*! Returns what setBody() set. Used for SmtpBdat instances to
    coordinate the body.
*/

String SMTP::body() const
{
    return d->body;
}


/*! Returns true if \a c is the oldest command in the SMTP server's
    queue of outstanding commands, and false if the queue is empty or
    there is a command older than \a c in the queue.
*/

bool SMTP::isFirstCommand( SmtpCommand * c ) const
{
    if ( c == d->commands.firstElement() )
        return true;
    return false;
}


class SMTPSData
    : public Garbage
{
public:
    SMTPSData() : tlsServer( 0 ), helper( 0 ) {}
    TlsServer * tlsServer;
    String banner;
    class SmtpsHelper * helper;
};

class SmtpsHelper: public EventHandler
{
public:
    SmtpsHelper( SMTPS * connection ) : c( connection ) {}
    void execute() { c->finish(); }

private:
    SMTPS * c;
};

/*! \class SMTPS smtp.h

    The SMTPS class implements the old wrapper trick still commonly
    used on port 465. As befits a hack, it is a bit of a hack, and
    depends on the ability to empty its writeBuffer().
*/

/*! Constructs an SMTPS server on file descriptor \a s, and starts to
    negotiate TLS immediately.
*/

SMTPS::SMTPS( int s )
    : SMTPSubmit( s ), d( new SMTPSData )
{
    String * tmp = writeBuffer()->removeLine();
    if ( tmp )
        d->banner = *tmp;
    d->helper = new SmtpsHelper( this );
    d->tlsServer = new TlsServer( d->helper, peer(), "SMTPS" );
    EventLoop::global()->removeConnection( this );
}


/*! Handles completion of TLS negotiation and sends the banner. */

void SMTPS::finish()
{
    if ( !d->tlsServer->done() )
        return;
    if ( !d->tlsServer->ok() ) {
        log( "Cannot negotiate TLS", Log::Error );
        close();
        return;
    }

    startTls( d->tlsServer );
    enqueue( d->banner + "\r\n" );
}
