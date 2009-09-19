// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "smtpclient.h"

#include "dsn.h"
#include "log.h"
#include "scope.h"
#include "timer.h"
#include "buffer.h"
#include "configuration.h"
#include "recipient.h"
#include "eventloop.h"
#include "address.h"
#include "message.h"

#include <time.h> // time()


static List<EventHandler> * waiting;
static uint serviced;


class SmtpClientData
    : public Garbage
{
public:
    SmtpClientData()
        : state( Invalid ), dsn( 0 ),
          owner( 0 ), log( 0 ), sentMail( false ),
          enhancedstatuscodes( false )
    {}

    enum State { Invalid,
                 Connected, Banner, Hello,
                 MailFrom, RcptTo, Data, Body,
                 Error, Rset, Quit };
    State state;

    EString sent;
    EString error;
    DSN * dsn;
    EventHandler * owner;
    Log * log;
    bool sentMail;
    List<Recipient>::Iterator rcptTo;
    List<Recipient> accepted;

    bool enhancedstatuscodes;
    Timer * closeTimer;
    class TimerCloser
        : public EventHandler
    {
    public:
        TimerCloser( SmtpClient * c ) : t( c ) {}
        void execute() { if ( t ) t->logout( 0 ); t = 0; }
        SmtpClient * t;
    };
    TimerCloser * timerCloser;
};


/*! \class SmtpClient smtpclient.h

    The SmtpClient class provides an SMTP client, as the alert reader
    will have inferred from its name.

    Archiveopteryx uses it to send outgoing messages to a smarthost.

*/

/*! Constructs an SMTP client which will immediately connect to \a
    address and introduce itself, and then wait politely for something
    to do.
*/

SmtpClient::SmtpClient( const Endpoint & address )
    : Connection( Connection::socket( address.protocol() ),
                  Connection::SmtpClient ),
      d( new SmtpClientData )
{
    connect( address );
    EventLoop::global()->addConnection( this );
    setTimeoutAfter( 4 );
    log( "Connecting to " + address.string() );
    d->timerCloser = new SmtpClientData::TimerCloser( this );
}


void SmtpClient::react( Event e )
{
    Scope x( d->log );

    Connection::State s1 = Connection::state();
    SmtpClientData::State s2 = d->state;
    EString s3 = d->error;
    switch ( e ) {
    case Read:
        parse();
        break;

    case Timeout:
        log( "SMTP server timed out", Log::Error );
        d->error = "Server timeout.";
        finish();
        close();
        break;

    case Connect:
        d->state = SmtpClientData::Connected;
        setTimeoutAfter( 300 );
        break; // we'll get a banner

    case Error:
    case Close:
        if ( state() == Connecting ) {
            d->error = "Connection refused by SMTP/LMTP server";
            finish( "4.4.1" );
        }
        else if ( d->state != SmtpClientData::Invalid &&
                  d->sent != "quit" ) {
            log( "Unexpected close by server", Log::Error );
            d->error = "Unexpected close by server.";
            finish( "4.4.2" );
        }
        break;

    case Shutdown:
        // I suppose we might send quit, but then again, it may not be
        // legal at this point.
        break;
    }

    if ( d->owner &&
         ( s1 != Connection::state() || s2 != d->state || s3 != d->error ) )
        d->owner->notify();
    if ( !d->owner && ready() && ::waiting && !waiting->isEmpty() ) {
        ::serviced = (uint)time( 0 );
        ::waiting->shift()->notify();
    }
}


/*! Reads and reacts to SMTP/LMTP responses. Sends new commands. */

void SmtpClient::parse()
{
    Buffer * r = readBuffer();

    while ( true ) {
        EString * s = r->removeLine();
        if ( !s )
            return;
        extendTimeout( 10 );
        log( "Received: " + *s, Log::Debug );
        bool ok = false;
        uint response = s->mid( 0, 3 ).number( &ok );
        if ( !ok ) {
            // nonnumeric response
            d->error = "Server sent garbage: " + *s;
        }
        else if ( (*s)[3] == '-' ) {
            if ( d->state == SmtpClientData::Hello ) {
                recordExtension( *s );
            }
        }
        else if ( (*s)[3] == ' ' ) {
            switch ( response/100 ) {
            case 1:
                d->error = "Server sent 1xx response: " + *s;
                break;
            case 2:
                if ( d->state == SmtpClientData::Connected )
                    d->state = SmtpClientData::Banner;
                if ( d->state == SmtpClientData::Hello )
                    recordExtension( *s );
                if ( d->rcptTo )
                    d->accepted.append( d->rcptTo );
                sendCommand();
                break;
            case 3:
                if ( d->state == SmtpClientData::Data ) {
                    log( "Sending body.", Log::Debug );
                    enqueue( dotted( d->dsn->message()->rfc822() ) );
                    d->state = SmtpClientData::Body;
                }
                else {
                    d->error = "Server sent inappropriate 3xx response: " + *s;
                }
                break;
            case 4:
            case 5:
                handleFailure( *s );
                if ( response == 421 ) {
                    log( "Closing because the SMTP server sent 421" );
                    close();
                    d->state = SmtpClientData::Invalid;
                }
                break;
            default:
                ok = false;
                break;
            }
        }

        if ( !ok ) {
            log( "L/SMTP error for command " + d->sent + ": " + *s,
                 Log::Error );
        }
    }
    if ( EventLoop::global()->inShutdown() )
        close();
}


/*! Sends a single SMTP command. */

void SmtpClient::sendCommand()
{
    EString send;

    switch( d->state ) {
    case SmtpClientData::Invalid:
        break;

    case SmtpClientData::Data:
        d->state = SmtpClientData::Body;
        break;

    case SmtpClientData::Connected:
        break;

    case SmtpClientData::Banner:
        send = "ehlo " + Configuration::hostname();
        d->state = SmtpClientData::Hello;
        break;

    case SmtpClientData::Hello:
        if ( !d->dsn )
            return;
        send = "mail from:<";
        if ( d->dsn->sender()->type() == Address::Normal )
            send.append( d->dsn->sender()->lpdomain() );
        send.append( ">" );

        d->state = SmtpClientData::MailFrom;
        break;

    case SmtpClientData::MailFrom:
    case SmtpClientData::RcptTo:
        if ( d->state == SmtpClientData::MailFrom ) {
            d->rcptTo = d->dsn->recipients()->first();
            d->state = SmtpClientData::RcptTo;
        }
        else {
            ++d->rcptTo;
        }
        while ( d->rcptTo && d->rcptTo->action() != Recipient::Unknown )
            ++d->rcptTo;
        if ( d->rcptTo ) {
            send = "rcpt to:<" + d->rcptTo->finalRecipient()->lpdomain() + ">";
        }
        else {
            if ( !d->accepted.isEmpty() ) {
                send = "data";
                d->state = SmtpClientData::Data;
            }
            else {
                finish();
                send = "rset";
                d->state = SmtpClientData::Rset;
            }
        }
        break;

    case SmtpClientData::Body:
        if ( !d->accepted.isEmpty() ) {
            d->sentMail = true;
            List<Recipient>::Iterator i( d->accepted );
            while ( i ) {
                if ( i->action() == Recipient::Unknown ) {
                    i->setAction( Recipient::Relayed, "" );
                    log( "Sent to " + i->finalRecipient()->localpart() +
                         "@" + i->finalRecipient()->domain() );
                }
                ++i;
            }
        }
        finish();
        send = "rset";
        d->state = SmtpClientData::Rset;
        break;

    case SmtpClientData::Rset:
        finish();
        delete d->closeTimer;
        d->closeTimer = new Timer( d->timerCloser, 298 );
        return;

    case SmtpClientData::Error:
        finish();
        send = "rset";
        d->state = SmtpClientData::Rset;
        break;

    case SmtpClientData::Quit:
        close();
        break;
    }

    if ( send.isEmpty() )
        return;

    log( "Sending: " + send, Log::Debug );
    enqueue( send + "\r\n" );
    d->sent = send;
    setTimeoutAfter( 300 );
}


/*! Returns a dot-escaped version of \a s, with a dot-cr-lf
    appended. This function probably should change lone CR or LF
    characters to CRLF, but it doesn't yet.
*/

EString SmtpClient::dotted( const EString & s )
{
    EString r;
    uint i = 0;
    uint sol = true;
    while ( i < s.length() ) {
        if ( s[i] == '\r' ) {
            sol = true;
            r.append( "\r\n" );
            if ( s[i+1] == '\n' )
                i++;
        }
        else if ( s[i] == '\n' ) {
            sol = true;
            r.append( "\r\n" );
        }
        else {
            if ( sol && s[i] == '.' )
                r.append( '.' );
            r.append( s[i] );
            sol = false;
        }
        i++;
    }
    if ( !sol )
        r.append( "\r\n" );
    r.append( ".\r\n" );

    return r;
}


static EString enhancedStatus( const EString & l, bool e,
                              SmtpClientData::State s )
{
    if ( e && ( l[4] >= '2' || l[4] <= '5' ) && l[5] == '.' ) {
        int i = l.mid( 4 ).find( ' ' );
        if ( i > 5 )
            return l.mid( 4, i-4 );
    }
    bool ok = false;
    uint response = l.mid( 0, 3 ).number( &ok );
    if ( !ok || response < 200 || response >= 600 )
        return "4.0.0";
    EString r;
    switch ( response )
    {
    case 211: // System status, or system help reply
        r = "2.0.0";
        break;
    case 214: // Help message
        r = "2.0.0";
        break;
    case 220: // <domain> Service ready
        r = "2.0.0";
        break;
    case 221: // <domain> Service closing transmission channel
        r = "2.0.0";
        break;
    case 250: // Requested mail action okay, completed
        if ( s == SmtpClientData::MailFrom ||
             s == SmtpClientData::RcptTo )
            r = "2.1.0";
        else
            r = "2.0.0";
        break;
    case 251: // User not local; will forward to <forward-path>
        r = "2.1.0";
        break;
    case 252: // Cannot VRFY user, but will accept message and attempt delivery
        r = "2.0.0";
        break;
    case 354: // Start mail input; end with <CRLF>.<CRLF>
        r = "2.0.0";
        break;
    case 421: // <domain> Service not available, closing transmission channel
        r = "4.3.0";
        break;
    case 450: // Requested mail action not taken: mailbox unavailable
        r = "4.2.0";
        break;
    case 451: // Requested action aborted: local error in processing
        r = "4.2.0";
        break;
    case 452: // Requested action not taken: insufficient system storage
        r = "4.2.0";
        break;
    case 500: // Syntax error, command unrecognized
        r = "4.3.0";
        break;
    case 501: // Syntax error in parameters or arguments
        r = "4.3.0";
        break;
    case 502: // Command not implemented (see section 4.2.4)
        r = "4.3.0";
        break;
    case 503: // Bad sequence of commands
        r = "4.3.0";
        break;
    case 504: // Command parameter not implemented
        r = "4.3.0";
        break;
    case 550: // Requested action not taken: mailbox unavailable (e.g.,
        // mailbox not found, no access, or command rejected for policy
        // reasons)
        r = "5.2.0";
        break;
    case 551: // User not local; please try <forward-path>
        r = "5.2.0";
        break;
    case 552: // Requested mail action aborted: exceeded storage allocation
        r = "5.3.0"; // or 5.2.0?
        break;
    case 553: // Requested action not taken: mailbox name not allowed
        r = "5.2.0";
        break;
    case 554: // Transaction failed  (Or, in the case of a
        // connection-opening response, "No SMTP service here")
        r = "5.0.0";
        break;
    default:
        r = fn( response/100 ) + ".0.0";
        break;
    }
    return r;
}


/*! Reacts appropriately to any failure.  Assumes that \a line is a
    complete SMTP reply line, including three-digit status code.
*/

void SmtpClient::handleFailure( const EString & line )
{
    EString status = enhancedStatus( line, d->enhancedstatuscodes,
                                    d->state );
    bool permanent = false;
    if ( line[0] == '5' )
        permanent = true;

    if ( d->state == SmtpClientData::RcptTo ) {
        if ( permanent )
            d->rcptTo->setAction( Recipient::Failed, status );
        else
            d->rcptTo->setAction( Recipient::Delayed, status );
    }
    else {
        List<Recipient>::Iterator i;
        if ( d->dsn )
            i = d->dsn->recipients();
        while ( i ) {
            if ( i->action() == Recipient::Unknown ) {
                if ( permanent )
                    i->setAction( Recipient::Failed, status );
                else
                    i->setAction( Recipient::Delayed, status );
            }
            ++i;
        }
        d->state = SmtpClientData::Error;
    }
    sendCommand();
}


/*! Returns true if this SmtpClient is ready to send() mail.
    SmtpClient notifies its owner when it becomes ready. */

bool SmtpClient::ready() const
{
    if ( d->dsn )
        return false;
    if ( d->state == SmtpClientData::Invalid ||
         d->state == SmtpClientData::Connected ||
         d->state == SmtpClientData::Hello ||
         d->state == SmtpClientData::Rset )
        return true;
    return false;
}


/*! Starts sending the message held by \a dsn with the right sender and
    recipients. Updates the \a dsn and its recipients with information
    about which recipients fail or succeed, and how. Notifies \a user
    when it's done.

    Does not use DSN::envelopeId() at present.
*/

void SmtpClient::send( DSN * dsn, EventHandler * user )
{
    if ( !ready() )
        return;

    d->log = new Log( user->log() );
    Scope x( d->log );

    EString s( "Sending message to " );
    s.append(  peer().address() );
    if ( !dsn->message()->header()->messageId().isEmpty() ) {
        s.append( ", message-id " );
        s.append( dsn->message()->header()->messageId() );
    }
    if ( !dsn->envelopeId().isEmpty() ) {
        s.append( ", envid " );
        s.append( dsn->envelopeId() );
    }
    s.append( ", from " );
    s.append( dsn->sender()->toString() );
    log( s );

    d->dsn = dsn;
    d->owner = user;
    d->sentMail = false;
    delete d->closeTimer;
    d->closeTimer = 0;
    if ( d->state == SmtpClientData::Rset )
        d->state = SmtpClientData::Hello;
    sendCommand();
}


/*! Finishes message sending activities, however they turned out, and
    notifies the user. If \a status is supplied and nonempty, \a
    status is used as Recipient::status() for all unhandled
    recipients.
*/

void SmtpClient::finish( const char * status )
{
    if ( status && *status && d->dsn ) {
        List<Recipient>::Iterator i( d->dsn->recipients() );
        while ( i ) {
            if ( i->action() == Recipient::Unknown )
                i->setAction( Recipient::Delayed, status );
            ++i;
        }
    }

    if ( d->owner )
        d->owner->notify();
    d->dsn = 0;
    d->owner = 0;
    d->log = 0;
}


/*! Parses \a line assuming it is an extension announcement, and
    records the extensions found. Parse errors, unknown extensions and
    so on are silently ignored.
*/

void SmtpClient::recordExtension( const EString & line )
{
    EString l = line.mid( 4 ).simplified();
    EString w = l;
    int s = l.find( ' ' );
    if ( s > 0 )
        w = w.mid( 0, s );
    w = w.lower();

    if ( w == "enhancedstatuscodes" )
        d->enhancedstatuscodes = true;
}


/*! Sends quit after \a t seconds. \a t must not be 0.

    Any subsequent use of the SmtpClient cancels the logout.
*/

void SmtpClient::logout( uint t )
{
    if ( d->state != SmtpClientData::Rset )
        return;
    if ( t ) {
        delete d->closeTimer;
        d->closeTimer = new Timer( d->timerCloser, t );
        return;
    }
    Scope x( log() );
    if ( d->log )
        x.setLog( d->log );
    d->state = SmtpClientData::Quit;
    log( "Sending: quit", Log::Debug );
    enqueue( "quit\r\n" );
    d->sent = "quit";
    setTimeoutAfter( 300 );
}


/*! Returns the client's error string, which is empty if no error has
    occurred.
*/

EString SmtpClient::error() const
{
    return d->error;
}


class SmtpClientBouncer
    : public EventHandler
{
public:
    SmtpClientBouncer() {}
    void execute();
};

void SmtpClientBouncer::execute()
{
    if ( !::waiting || ::waiting->isEmpty() ||
         ::serviced + 7 > (uint)time( 0 ) )
        return;

    Endpoint e( Configuration::text( Configuration::SmartHostAddress ),
                Configuration::scalar( Configuration::SmartHostPort ) );
    (void)new SmtpClient( e );
    ::waiting->shift()->notify();
}




/*! Requests the attentions of an SMTP client.

    If one is ready() for use now, request() returns its address. If
    not, request() queues \a h and notifies it as soon as an SMTP
    client becomes ready(). \a h needs to call request() again at that
    time.
*/

SmtpClient * SmtpClient::request( EventHandler * h )
{
    List<SmtpClient>::Iterator c( clients() );
    if ( !c ) {
        Endpoint e( Configuration::text( Configuration::SmartHostAddress ),
                    Configuration::scalar( Configuration::SmartHostPort ) );
        (void)new SmtpClient( e );
        c = clients();
    }

    while ( c && !c->ready() )
        ++c;
    if ( c ) {
        if ( ::waiting )
            ::waiting->take( ::waiting->find( h ) );
        ::serviced = ::time( 0 );
        return c;
    }

    if ( !::waiting ) {
        ::waiting = new List<EventHandler>;
        Allocator::addEternal( ::waiting, "event handlers waiting for smtp" );
    }
    if ( !waiting->find( h ) )
        ::waiting->append( h );
    (void)new Timer( new SmtpClientBouncer, 7 );
    ::log( "Queuing for SMTP client access (" + fn( clients()->count() ) +
           " clients to serve " + fn( ::waiting->count() ) + " agents)" );
    return 0;
}


/*! Returns true if the most recent transmission attempt worked for at
    least one recipient, and false if not.
*/

bool SmtpClient::sent() const
{
    return d->sentMail;
}


/*! Returns a list of all extant SMTP clients. The list will never be
 *  null, but it may be empty.
*/

List<SmtpClient> * SmtpClient::clients()
{
    List<SmtpClient> * l = new List<SmtpClient>;
    List<Connection>::Iterator c( EventLoop::global()->connections() );
    while ( c ) {
        if ( c->type() == Connection::SmtpClient ) {
            Connection * tmp = c;
            l->append( (SmtpClient*)tmp );
        }
        ++c;
    }
    return l;
}
