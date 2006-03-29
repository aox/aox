// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "smtpclient.h"

#include "log.h"
#include "buffer.h"
#include "configuration.h"
#include "eventloop.h"


class SmtpClientData
    : public Garbage
{
public:
    SmtpClientData()
        : failed( false ), connected( false ), owner( 0 )
    {}

    bool failed;
    bool connected;

    String sent;
    String error;
    String sender;
    String message;
    String recipient;
    EventHandler *owner;
};


/*! \class SmtpClient smtpclient.h

    The SmtpClient class provides an SMTP or LMTP client. It's a
    little in the primitive side, but enough to talk to our own LMTP
    server, or to the SMTP server of a smarthost.

    Right now, this class is used only by bin/deliver. It is unable to
    handle multiple recipients (or mailboxes), partly because it's not
    needed, and partly because there's no sane way to indicate failure
    with multiple recipients. It is also hardwired to talk to our own
    LMTP server. (All this may change in the future.)
*/

/*! Constructs an SMTP client to send \a message to \a recipient from
    \a sender, on behalf of \a owner.
*/

SmtpClient::SmtpClient( const String &sender,
                        const String &message,
                        const String &recipient,
                        EventHandler *owner )
    : Connection( Connection::socket( Endpoint::IPv4 ),
                  Connection::SmtpClient ),
      d( new SmtpClientData )
{
    d->owner = owner;
    d->sender = sender;
    d->message = message;
    d->recipient = recipient;

    Endpoint e( Configuration::LmtpAddress, Configuration::LmtpPort );
    if ( !e.valid() ) {
        d->error = "Invalid server";
        d->failed = true;
        d->owner->execute();
        return;
    }
    connect( e );
    EventLoop::global()->addConnection( this );
    setTimeoutAfter( 10 ); // ### not RFC-compliant
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
        d->failed = true;
        d->owner->execute();
        break;

    case Connect:
        d->connected = true;
        break; // we'll get a banner

    case Error:
    case Close:
        if ( !d->connected ) {
            d->error = "Connection refused by SMTP/LMTP server";
            d->failed = true;
            d->owner->execute();
        }
        else if ( d->sent != "quit" ) {
            log( "Unexpected close by server", Log::Error );
            d->error = "Unexpected close by server.";
            d->failed = true;
            d->owner->execute();
        }
        break;

    case Shutdown:
        // I suppose we might send quit, but then again, it may not be
        // legal at this point.
        break;
    }
}


/*! Returns true if this client encountered an error while attempting
    delivery, and false otherwise.
*/

bool SmtpClient::failed() const
{
    return d->failed;
}


/*! Returns the last error seen, or an empty string if no error has been
    encountered. Will be set if failed() is true.
*/

String SmtpClient::error() const
{
    return d->error;
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
        if ( (*s)[3] == '-' ) {
            // it's a continuation line
            ok = true;
        }
        else if ( d->sent == "data" ) {
            if ( (*s)[0] == '3' ) {
                ok = true;
                log( "Sending body.", Log::Debug );
                enqueue( dotted( d->message ) );
                d->sent = "body";
            }
        }
        else {
            if ( (*s)[0] == '2' ) {
                ok = true;
                sendCommand();
            }
        }
        if ( !ok ) {
            d->error = *s;
            d->failed = true;
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
    switch ( d->sent[0] ) {
    case '\0':
        if ( peer().port() != 25 )
            send = "lhlo";
        else
            send = "helo";
        send = send + " " + Configuration::hostname();
        break;
    case 'e':
    case 'h':
    case 'l':
        send = "mail from:<" + d->sender + ">";
        break;
    case 'm':
        send = "rcpt to:<" + d->recipient + ">";
        break;
    case 'r':
        send = "data";
        break;
    case 'b':
        send = "quit";
        break;
    case 'q':
    default:
        setState( Closing );
        d->owner->execute();
        commit();
        return;
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
