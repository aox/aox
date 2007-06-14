// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpclient.h"

#include "dsn.h"
#include "log.h"
#include "scope.h"
#include "buffer.h"
#include "configuration.h"
#include "recipient.h"
#include "eventloop.h"
#include "address.h"
#include "message.h"


class SmtpClientData
    : public Garbage
{
public:
    SmtpClientData()
        : state( Invalid ), dsn( 0 ),
          owner( 0 ), user( 0 ),
          enhancedstatuscodes( false )
    {}

    enum State { Invalid,
                 Connected, Hello,
                 MailFrom, RcptTo, Data, Body,
                 Error, Rset, Quit };
    State state;

    String sent;
    String error;
    DSN * dsn;
    EventHandler * owner;
    EventHandler * user;
    List<Recipient>::Iterator rcptTo;

    bool enhancedstatuscodes;
};


/*! \class SmtpClient smtpclient.h

    The SmtpClient class provides an SMTP client, as the alert reader
    will have inferred from its name.

    Archiveopteryx uses it to send outgoing messages to a smarthost.
    
*/

/*! Constructs an SMTP client which will immediately connect to \a
    address and introduce itself, and which notifies \a owner whenever
    it becomes ready() to deliver another message.
*/

SmtpClient::SmtpClient( const Endpoint & address, EventHandler * owner )
    : Connection( Connection::socket( address.protocol() ),
                  Connection::SmtpClient ),
      d( new SmtpClientData )
{
    Scope s( log() );
    d->owner = owner;
    connect( address );
    EventLoop::global()->addConnection( this );
    setTimeoutAfter( 300 );
    log( "Connecting to " + address.string() );
}


void SmtpClient::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    case Timeout:
        log( "SMTP/LMTP server timed out", Log::Error );
        Connection::setState( Closing );
        d->error = "Server timeout.";
        finish();
        d->owner->execute();
        break;

    case Connect:
        d->state = SmtpClientData::Connected;
        break; // we'll get a banner

    case Error:
    case Close:
        if ( state() == Connecting ) {
            d->error = "Connection refused by SMTP/LMTP server";
            finish();
            d->owner->execute();
        }
        else if ( d->sent != "quit" ) {
            log( "Unexpected close by server", Log::Error );
            d->error = "Unexpected close by server.";
            finish();
            d->owner->execute();
        }
        break;

    case Shutdown:
        // I suppose we might send quit, but then again, it may not be
        // legal at this point.
        break;
    }
}


/*! Reads and reacts to SMTP/LMTP responses. Sends new commands. */

void SmtpClient::parse()
{
    Buffer * r = readBuffer();

    while ( true ) {
        String * s = r->removeLine();
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
                if ( d->state == SmtpClientData::Hello )
                    recordExtension( *s );
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
                if ( response == 421 )
                    setState( Closing );
                break;
            default:
                ok = false;
                break;
            }
        }

        if ( !ok ) {
            d->owner->execute();
            log( "L/SMTP error for command " + d->sent + ": " + *s,
                 Log::Error );
        }
    }
}


/*! Sends a single SMTP command. */

void SmtpClient::sendCommand()
{
    String send;

    switch( d->state ) {
    case SmtpClientData::Invalid:
        break;
    case SmtpClientData::Data:
        d->state = SmtpClientData::Body;
        break;

    case SmtpClientData::Rset:
    case SmtpClientData::Connected:
        send = "ehlo " + Configuration::hostname();
        d->state = SmtpClientData::Hello;
        break;

    case SmtpClientData::Hello:
        if ( !d->dsn )
            return;
        send = "mail from:<" + d->dsn->sender()->toString() + ">";
        d->state = SmtpClientData::MailFrom;
        break;

    case SmtpClientData::MailFrom:
    case SmtpClientData::RcptTo:
        if ( d->state == SmtpClientData::MailFrom )
            d->rcptTo = d->dsn->recipients()->first();
        else
            ++d->rcptTo;
        while ( d->rcptTo && d->rcptTo->action() != Recipient::Unknown )
            ++d->rcptTo;
        if ( d->rcptTo ) {
            send = "rcpt to:<" +
                   d->rcptTo->finalRecipient()->localpart() + "@" +
                   d->rcptTo->finalRecipient()->domain() + ">";
        }
        else {
            List<Recipient>::Iterator i( d->dsn->recipients() );
            while ( i && !i->action() != Recipient::Unknown )
                ++i;
            if ( i ) {
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

    case SmtpClientData::Error:
    case SmtpClientData::Body:
        finish();
        send = "rset";
        d->state = SmtpClientData::Rset;
        break;

    case SmtpClientData::Quit:
        Connection::setState( Connection::Closing );
        break;
    }

    log( "Sending: " + send, Log::Debug );
    enqueue( send + "\r\n" );
    d->sent = send;
}


/*! Returns a dot-escaped version of \a s, with a dot-cr-lf
    appended. This function probably should change lone CR or LF
    characters to CRLF, but it doesn't yet.
*/

String SmtpClient::dotted( const String & s )
{
    String r;
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


static String enhancedStatus( const String & l, bool e, 
                              SmtpClientData::State s )
{
    if ( e && ( l[4] >= '2' || l[4] <= '5' ) && l[5] == '.' ) {
        int i = l.mid( 4 ).find( ' ' );
        if ( i > 5 )
            return l.mid( 4, i-4 );
    }
    bool ok = false;
    uint response = l.mid( 0, 3 ).number( &ok );
    if ( response < 200 | response >= 600 || !ok )
        return "4.0.0";
    String r;
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

void SmtpClient::handleFailure( const String & line )
{
    String status = enhancedStatus( line, d->enhancedstatuscodes,
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
        List<Recipient>::Iterator i( d->dsn->recipients() );
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
    SmtpClient notifies its owner() when it becomes ready. */

bool SmtpClient::ready() const
{
    if ( d->dsn )
        return false;
    if ( d->state == SmtpClientData::Hello )
        return true;
    return false;
}


/*! Returns true if this SmtpClient may be used, either immediately or
    at some time in the future after it becomes ready(), to send() a
    message. It returns false otherwise, and the caller should use a
    new SmtpClient object.
*/

bool SmtpClient::usable() const
{
    // XXX: I'm not certain that this is sufficient.
    if ( d->error.isEmpty() )
        return true;
    return false;
}


/*! Starts sending the message held by \a dsn with with the right
    sender and recipients. Updates the \a dsn and its recipients with
    information about which recipients fail or succeed, and how.

    Does not use DSN::envid() at present.
*/

void SmtpClient::send( DSN * dsn, EventHandler * user )
{
    if ( !ready() )
        return;

    d->dsn = dsn;
    d->user = user;
    sendCommand();
}


/*! Finishes message sending activities, however they turned out, and
    notifies the user.
*/

void SmtpClient::finish()
{
    if ( d->user )
        d->user->execute();
    d->dsn = 0;
    d->user = 0;
}


/*! Parses \a line assuming it is an extension announcement, and
    records the extensions found. Parse errors, unknown extensions and
    so on are silently ignored.
*/

void SmtpClient::recordExtension( const String & line )
{
    String l = line.mid( 4 ).simplified();
    String w = l;
    int s = l.find( ' ' );
    if ( s > 0 )
        w = w.mid( 0, s );
    w = w.lower();

    if ( w == "enhancedstatuscodes" )
        d->enhancedstatuscodes = true;
}
