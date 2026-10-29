// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "autoconfig.h"

#include "ace.h"
#include "handler.h"
#include "utf.h"
#include "http.h"
#include "query.h"
#include "ustring.h"
#include "configuration.h"
#include "estringlist.h"


class AutoconfigData
    : public Garbage
{
public:
    AutoconfigData(): http( 0 ), q( 0 ) {}

    HTTP * http;
    Query * q;
};


/*! \class Autoconfig autoconfig.h

    The Autoconfig class generates the mail autoconfiguration document
    described by draft-ietf-mailmaint-autoconfig, which a client fetches
    to learn how to talk to us before it has an account to ask with.

    The protocols and ports come from the running configuration and
    database, so a server that does not offer POP does not advertise
    POP, and one without TLS admits it.
*/


static EString xmlEscaped( const EString & s )
{
    EString r;
    uint i = 0;
    while ( i < s.length() ) {
        if ( s[i] == '&' )
            r.append( "&amp;" );
        else if ( s[i] == '<' )
            r.append( "&lt;" );
        else if ( s[i] == '>' )
            r.append( "&gt;" );
        else if ( s[i] == '"' )
            r.append( "&quot;" );
        else
            r.append( s[i] );
        i++;
    }
    return r;
}


/*! Returns \a s as UTF-8, with any punycode decoded, so that a human
    reading the document sees the name as it is written rather than as
    the DNS carries it.
*/

static EString unicodeForm( const UString & s )
{
    Utf8Codec u;
    return u.fromUnicode( ACE::decode( s ) );
}


/*! Appends to \a r a server element of kind \a kind (incomingServer or
    outgoingServer) and type \a type, on \a hostname and \a port, using
    \a socketType.
*/

static void server( EString & r,
                    const EString & kind, const EString & type,
                    const EString & hostname, uint port,
                    const EString & socketType )
{
    bool cleartext = ( Configuration::toggle( Configuration::AuthPlain ) ||
                       Configuration::toggle( Configuration::AuthLogin ) );
    bool encrypted = ( Configuration::toggle( Configuration::AuthCramMd5 ) ||
                       Configuration::toggle( Configuration::AuthDigestMd5 ) );
    // Without TLS the server itself refuses cleartext passwords when
    // allow-plaintext-passwords is never, so we must not promise them.
    if ( socketType == "plain" &&
         Configuration::text( Configuration::AllowPlaintextPasswords )
         .lower() == "never" )
        cleartext = false;

    EStringList authentication;
    if ( socketType == "plain" ) {
        if ( encrypted )
            authentication.append( "password-encrypted" );
        if ( cleartext )
            authentication.append( "password-cleartext" );
    }
    else {
        if ( cleartext )
            authentication.append( "password-cleartext" );
        if ( encrypted )
            authentication.append( "password-encrypted" );
    }
    if ( authentication.isEmpty() )
        return;

    r.append( "  <" + kind + " type=\"" + type + "\">\n" );
    r.append( "   <hostname>" + xmlEscaped( hostname ) + "</hostname>\n" );
    r.append( "   <port>" + fn( port ) + "</port>\n" );
    r.append( "   <socketType>" + socketType + "</socketType>\n" );
    EStringList::Iterator i( authentication );
    while ( i ) {
        r.append( "   <authentication>" + *i + "</authentication>\n" );
        ++i;
    }
    r.append( "   <username>%EMAILADDRESS%</username>\n" );
    r.append( "  </" + kind + ">\n" );
}


class AutoconfigHandler
    : public HttpHandler
{
public:
    AutoconfigHandler( const EString & path ): HttpHandler( path ) {}

    void handle( HTTP * http )
    {
        if ( http->method() != "GET" && http->method() != "HEAD" ) {
            http->setStatus( 405, "Only GET and HEAD serve " + path() );
            http->addHeader( "Allow: GET, HEAD" );
            http->respond( "text/plain",
                           "Only GET and HEAD serve " + path() + "\n" );
            return;
        }
        (void)new Autoconfig( http );
    }
};


/*! Registers the autoconfiguration URL. The server calls this at
    startup if it serves HTTP at all.
*/

void Autoconfig::setup()
{
    (void)new AutoconfigHandler(
        "/.well-known/autoconfig/mail/config-v1.1.xml" );
}


/*! Constructs an Autoconfig which will answer the request \a http is
    serving, once it knows which domains to claim.
*/

Autoconfig::Autoconfig( HTTP * http )
    : d( new AutoconfigData )
{
    d->http = http;
    d->q = new Query( "select distinct a.domain from addresses a "
                      "join aliases al on (al.address=a.id) "
                      "order by a.domain", this );
    d->q->execute();
}


void Autoconfig::execute()
{
    if ( !d->q->done() )
        return;

    if ( d->q->failed() ) {
        d->http->setStatus( 503, "Cannot read the list of domains" );
        d->http->respond( "text/plain",
                          "Cannot read the list of domains.\n" );
        return;
    }

    EStringList domains;
    while ( d->q->hasResults() ) {
        UString domain = d->q->nextRow()->getUString( "domain" );
        Utf8Codec u;
        EString stored = u.fromUnicode( domain );
        domains.append( stored );
        EString unicode = unicodeForm( domain );
        if ( unicode != stored )
            domains.append( unicode );
    }

    EString hostname = Configuration::hostname();
    if ( domains.isEmpty() )
        domains.append( hostname );

    AsciiCodec a;
    EString display = unicodeForm( a.toUnicode( hostname ) );
    if ( !a.valid() )
        display = hostname;

    EString plain( "plain" );
    if ( Configuration::toggle( Configuration::UseTls ) )
        plain = "STARTTLS";

    EString r( "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" );
    r.append( "<clientConfig version=\"1.2\">\n" );
    r.append( " <emailProvider id=\"" + xmlEscaped( hostname ) + "\">\n" );
    EStringList::Iterator i( domains );
    while ( i ) {
        r.append( "  <domain>" + xmlEscaped( *i ) + "</domain>\n" );
        ++i;
    }
    r.append( "  <displayName>" + xmlEscaped( display ) + "</displayName>\n" );

    // Implicit TLS first, since RFC8314 2 prefers it to STARTTLS.
    if ( Configuration::toggle( Configuration::UseImaps ) )
        server( r, "incomingServer", "imap", hostname,
                Configuration::scalar( Configuration::ImapsPort ), "SSL" );
    if ( Configuration::toggle( Configuration::UseImap ) )
        server( r, "incomingServer", "imap", hostname,
                Configuration::scalar( Configuration::ImapPort ), plain );
    if ( Configuration::toggle( Configuration::UsePops ) )
        server( r, "incomingServer", "pop3", hostname,
                Configuration::scalar( Configuration::PopsPort ), "SSL" );
    if ( Configuration::toggle( Configuration::UsePop ) )
        server( r, "incomingServer", "pop3", hostname,
                Configuration::scalar( Configuration::PopPort ), plain );
    if ( Configuration::toggle( Configuration::UseSmtps ) )
        server( r, "outgoingServer", "smtp", hostname,
                Configuration::scalar( Configuration::SmtpsPort ), "SSL" );
    if ( Configuration::toggle( Configuration::UseSmtpSubmit ) )
        server( r, "outgoingServer", "smtp", hostname,
                Configuration::scalar( Configuration::SmtpSubmitPort ),
                plain );

    r.append( " </emailProvider>\n" );
    r.append( "</clientConfig>\n" );

    d->http->respond( "text/xml", r );
}
