#include "smtpclient.h"

#include "log.h"
#include "buffer.h"
#include "configuration.h"
#include "loop.h"


class SmtpClientData {
public:
    SmtpClientData()
        : failed( false ), owner( 0 )
    {}

    bool failed;
    
    String sent;
    String sender;
    String message;
    String recipient;
    EventHandler *owner;
};


/*! \class SmtpClient smtpclient.h

    The SmtpClient class provides an SMTP or LMTP client. It's a
    little in the primitive side, but enough to talk to our own LMTP
    server, or to the SMTP server of a smarthost.

    Right now the constructor is hardwired to talk to our own LMTP
    server.
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

    connect( Endpoint( "127.0.0.1", 2026 ) );
    Loop::addConnection( this );
    setTimeoutAfter( 10 );
}


/*! \reimp */

SmtpClient::~SmtpClient()
{
    Loop::removeConnection( this );
}


/*! \reimp */

void SmtpClient::react( Event e )
{
    switch ( e ) {
    case Read:
        parse();
        break;

    case Timeout:
        log( Log::Error, "SMTP/LMTP server timed out" );
        Connection::setState( Closing );
        d->owner->notify();
        break;

    case Connect:
        break; // we'll get a banner

    case Error:
    case Close:
        if ( d->sent != "quit" ) {
            log( Log::Error, "Unexpected close by server" );
            d->owner->notify();
        }
        break;

    case Shutdown:
        Connection::setState( Closing );
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


/*! Reads and reacts to SMTP/LMTP responses. Sends new commands. */

void SmtpClient::parse()
{
    Buffer * r = readBuffer();

    while ( true ) {
        String * s = r->removeLine();
        if ( !s )
            return;
        extendTimeout( 10 );
        log( Log::Debug, "Received: " + *s );
        bool ok = false;
        if ( (*s)[3] == '-' ) {
            // it's a continuation line
            ok = true;
        }
        else if ( d->sent == "data" ) {
            if ( (*s)[0] == '3' ) {
                ok = true;
                log( Log::Debug, "Sending body." );
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
            d->failed = true;
            log( Log::Error, "SMTP/LMTP error for command " + d->sent );
            log( Log::Error, "Response: " + *s );
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
        d->owner->notify();
        return;
        break;
    }
    log( Log::Debug, "Sending: " + send );
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
    while ( i < s.length() ) {
        if ( s[i] == '.' &&
             ( i == 0 || s[i-1] == '\r' || s[i-1] == '\n' ) )
            r.append( "." );
        r.append( s[i] );
        i++;
    }
    i = r.length();
    if ( i < 2 || r[i-2] != '\r' || r[i-1] != '\n' )
        r.append( "\r\n" );
    r.append( ".\r\n" );
    return r;
}
