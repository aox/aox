// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "jmap.h"

#include "utf.h"
#include "method.h"
#include "emailquery.h"
#include "http.h"
#include "handler.h"
#include "json.h"
#include "user.h"
#include "ustring.h"
#include "mailbox.h"
#include "estringlist.h"
#include "configuration.h"


static const char * core = "urn:ietf:params:jmap:core";
static const char * mail = "urn:ietf:params:jmap:mail";


class JmapData
    : public Garbage
{
public:
    JmapData(): http( 0 ), user( 0 ), method( 0 ),
                authenticated( false ) {}

    HTTP * http;
    User * user;
    JmapMethod * method;
    EString callId;
    UString secret;
    bool authenticated;
};


/*! \class Jmap jmap.h

    The Jmap class answers one JMAP request: the session resource
    described in RFC8620 2, or an API call to the endpoint that session
    resource names.

    This is a read-only JMAP server. Not "a server whose write methods
    check a flag" - the methods that change anything are not here at
    all, so a request for one is answered with unknownMethod, the same
    answer RFC8620 3.5.1 prescribes for a method the server has never
    heard of. A client cannot tell the difference, and neither can a
    bug.

    Authentication is HTTP Basic for now, which is a placeholder and
    not conformant with the profile this serves: the profile requires
    that the credential cannot be used for read-write access, and a
    mail password plainly can, in IMAP. OAuth, or a read-only token,
    replaces this.
*/


class JmapHandler
    : public HttpHandler
{
public:
    JmapHandler( const EString & path ): HttpHandler( path ) {}

    void handle( HTTP * http ) { (void)new Jmap( http ); }
};


/*! Registers the session resource and the API endpoint. The server
    calls this at startup if it serves HTTP at all.
*/

void Jmap::setup()
{
    (void)new JmapHandler( "/.well-known/jmap" );
    (void)new JmapHandler( "/jmap/" );
}


/*! Constructs a Jmap to answer the request \a http is serving. */

Jmap::Jmap( HTTP * http )
    : d( new JmapData )
{
    d->http = http;
    execute();
}


void Jmap::execute()
{
    if ( !d->authenticated ) {
        authenticate();
        return;
    }

    if ( d->method ) {
        // an asynchronous method is answering; wait for it, then send
        // what it came up with
        if ( !d->method->done() )
            return;
        Json * response = Json::list();
        response->append( Json::string( d->method->responseName() ) );
        response->append( d->method->response() );
        response->append( Json::string( d->callId ) );
        Json * responses = Json::list();
        responses->append( response );
        Json * r = Json::object();
        r->insert( "methodResponses", responses );
        r->insert( "sessionState", Json::string( EString( "1" ) ) );
        d->method = 0;
        d->http->respond( "application/json", r->write() + "\n" );
        return;
    }

    if ( d->http->path() == "/jmap/" )
        serveApi();
    else
        serveSession();
}


/*! Answers \a status, naming the JMAP problem type \a type, with \a
    detail as the human-readable part. RFC8620 3.6.1 gives the shape.
*/

void Jmap::fail( uint status, const EString & type, const EString & detail,
                 const EString & limit )
{
    Json * r = Json::object();
    r->insert( "type", Json::string( type ) );
    r->insert( "status", Json::number( status ) );
    r->insert( "detail", Json::string( detail ) );
    // RFC8620 3.6.1: a limit error says which limit
    if ( !limit.isEmpty() )
        r->insert( "limit", Json::string( limit ) );
    d->http->setStatus( status, detail );
    d->http->respond( "application/problem+json", r->write() + "\n" );
}


/*! Works out who is asking, using HTTP Basic authentication, and
    answers 401 if it cannot.
*/

void Jmap::authenticate()
{
    if ( !d->user ) {
        EString a = d->http->header( "Authorization" );
        if ( !a.lower().startsWith( "basic " ) ) {
            // RFC8620 8.2: the server says how to authenticate. Basic
            // is what we have; a client offering Bearer or anything
            // else gets the same answer.
            d->http->setStatus( 401, "Authentication required" );
            d->http->addHeader( "WWW-Authenticate: Basic realm=\"JMAP\"" );
            fail( 401, "about:blank", "This API needs HTTP Basic "
                  "authentication" );
            return;
        }
        EString credentials = a.mid( 6 ).simplified().de64();
        int colon = credentials.find( ':' );
        if ( colon < 1 ) {
            d->http->setStatus( 401, "Malformed credentials" );
            fail( 401, "about:blank", "Malformed Basic credentials" );
            return;
        }
        if ( !d->http->encrypted() &&
             Configuration::text( Configuration::AllowPlaintextPasswords )
             .lower() == "never" ) {
            fail( 403, "about:blank",
                  "This server does not accept passwords "
                  "on unencrypted connections" );
            return;
        }
        Utf8Codec u;
        d->user = new User;
        d->user->setLogin( u.toUnicode( credentials.mid( 0, colon ) ) );
        d->secret = u.toUnicode( credentials.mid( colon + 1 ) );
        d->user->refresh( this );
    }

    if ( d->user->state() == User::Unverified )
        return;

    // A user with no password of its own - an LDAP user, say - cannot
    // authenticate here. This API has no business in the SASL path.
    if ( d->user->state() != User::Refreshed ||
         d->user->secret().isEmpty() ||
         d->user->secret() != d->secret ) {
        d->http->setStatus( 401, "Authentication failed" );
        d->http->addHeader( "WWW-Authenticate: Basic realm=\"JMAP\"" );
        fail( 401, "about:blank", "Authentication failed" );
        return;
    }

    d->authenticated = true;
    execute();
}


static Json * limits()
{
    Json * c = Json::object();
    // Nothing can be uploaded, so the upload limits are zero rather
    // than generous.
    c->insert( "maxSizeUpload", Json::number( 0 ) );
    c->insert( "maxConcurrentUpload", Json::number( 0 ) );
    c->insert( "maxSizeRequest", Json::number( 65536 ) );
    c->insert( "maxConcurrentRequests", Json::number( 4 ) );
    c->insert( "maxCallsInRequest", Json::number( 1 ) );
    c->insert( "maxObjectsInGet", Json::number( 64 ) );
    c->insert( "maxObjectsInSet", Json::number( 0 ) );
    Json * collations = Json::list();
    collations->append( Json::string( EString( "i;unicode-casemap" ) ) );
    c->insert( "collationAlgorithms", collations );
    return c;
}


static Json * mailCapabilities()
{
    Json * m = Json::object();
    m->insert( "maxMailboxesPerEmail", new Json( Json::Null ) );
    m->insert( "maxMailboxDepth", new Json( Json::Null ) );
    m->insert( "maxSizeMailboxName", Json::number( 255 ) );
    m->insert( "maxSizeAttachmentsPerEmail", Json::number( 0 ) );
    m->insert( "mayCreateTopLevelMailbox", Json::boolean( false ) );
    Json * sort = Json::list();
    sort->append( Json::string( EString( "receivedAt" ) ) );
    sort->append( Json::string( EString( "sentAt" ) ) );
    sort->append( Json::string( EString( "size" ) ) );
    sort->append( Json::string( EString( "from" ) ) );
    sort->append( Json::string( EString( "to" ) ) );
    sort->append( Json::string( EString( "subject" ) ) );
    m->insert( "emailQuerySortOptions", sort );
    return m;
}


/*! Sends the session resource of RFC8620 2. */

void Jmap::serveSession()
{
    if ( d->http->method() != "GET" && d->http->method() != "HEAD" ) {
        d->http->addHeader( "Allow: GET, HEAD" );
        fail( 405, "about:blank", "The session resource is read with GET" );
        return;
    }

    EString id = fn( d->user->id() );

    Json * capabilities = Json::object();
    capabilities->insert( core, limits() );
    capabilities->insert( mail, mailCapabilities() );

    Json * account = Json::object();
    account->insert( "name", Json::string( d->user->login() ) );
    account->insert( "isPersonal", Json::boolean( true ) );
    account->insert( "isReadOnly", Json::boolean( true ) );
    Json * ac = Json::object();
    ac->insert( core, Json::object() );
    ac->insert( mail, Json::object() );
    account->insert( "accountCapabilities", ac );

    Json * accounts = Json::object();
    accounts->insert( id, account );

    Json * primary = Json::object();
    primary->insert( mail, Json::string( id ) );

    Json * r = Json::object();
    r->insert( "capabilities", capabilities );
    r->insert( "accounts", accounts );
    r->insert( "primaryAccounts", primary );
    r->insert( "username", Json::string( d->user->login() ) );
    r->insert( "apiUrl", Json::string( EString( "/jmap/" ) ) );
    // Empty, because there is nothing there: no blob download yet, no
    // upload ever, and no push. A client reads these as "not
    // available" rather than following them to a 404.
    r->insert( "downloadUrl", Json::string( EString( "" ) ) );
    r->insert( "uploadUrl", Json::string( EString( "" ) ) );
    r->insert( "eventSourceUrl", Json::string( EString( "" ) ) );
    // This changes when the session object changes - when an account
    // appears or a capability does - not when mail arrives.
    r->insert( "state", Json::string( EString( "1" ) ) );

    d->http->respond( "application/json", r->write() + "\n" );
}


/*! Answers one method call, \a name with arguments \a arguments, and
    returns the response arguments. Returns a null pointer if the
    method is not one we implement.
*/

Json * Jmap::call( const EString & name, Json * arguments )
{
    if ( name == "Core/echo" )
        // RFC8620 4: the one method that is its own answer.
        return arguments;

    return 0;
}


/*! Starts the method \a name with \a arguments, if it is one that has
    to ask the database, and returns true. Returns false if \a name
    isn't a method.
*/

bool Jmap::start( const EString & name, Json * arguments,
                  const EString & callId )
{
    if ( name == "Email/query" )
        d->method = new EmailQuery( this, d->user, arguments );
    else
        return false;

    d->callId = callId;
    d->method->execute();
    return true;
}


/*! Answers a request to the API endpoint: RFC8620 3.3 describes the
    envelope, 3.6 the errors.
*/

void Jmap::serveApi()
{
    if ( d->http->method() != "POST" ) {
        d->http->addHeader( "Allow: POST" );
        fail( 405, "about:blank", "The API endpoint is used with POST" );
        return;
    }

    if ( d->http->body().length() > 65536 ) {
        fail( 400, "urn:ietf:params:jmap:error:limit",
              "The request is larger than maxSizeRequest",
              "maxSizeRequest" );
        return;
    }

    EString error;
    Json * request = Json::parse( d->http->body(), error );
    if ( !request ) {
        fail( 400, "urn:ietf:params:jmap:error:notJSON", error );
        return;
    }
    if ( !request->valid( Json::Object ) ) {
        fail( 400, "urn:ietf:params:jmap:error:notRequest",
              "The request must be a JSON object" );
        return;
    }

    Json * using_ = request->member( "using" );
    if ( !using_ || !using_->valid( Json::Array ) ) {
        fail( 400, "urn:ietf:params:jmap:error:notRequest",
              "The request must name the capabilities it uses" );
        return;
    }
    bool usesCore = false;
    List<Json>::Iterator u( using_->array() );
    while ( u ) {
        if ( u->valid( Json::String ) && u->ascii() == core )
            usesCore = true;
        ++u;
    }
    if ( !usesCore ) {
        fail( 400, "urn:ietf:params:jmap:error:unknownCapability",
              EString( "The request must use " ) + core );
        return;
    }

    Json * calls = request->member( "methodCalls" );
    if ( !calls || !calls->valid( Json::Array ) ) {
        fail( 400, "urn:ietf:params:jmap:error:notRequest",
              "The request must contain an array of method calls" );
        return;
    }
    if ( calls->array()->count() > 1 ) {
        fail( 400, "urn:ietf:params:jmap:error:limit",
              "This server answers one method call per request",
              "maxCallsInRequest" );
        return;
    }

    Json * responses = Json::list();
    List<Json>::Iterator c( calls->array() );
    while ( c ) {
        Json * invocation = c;
        ++c;
        if ( !invocation->valid( Json::Array ) ||
             invocation->array()->count() != 3 ) {
            fail( 400, "urn:ietf:params:jmap:error:notRequest",
                  "Each method call is a triple of name, arguments and id" );
            return;
        }
        List<Json>::Iterator i( invocation->array() );
        Json * name = i;
        ++i;
        Json * arguments = i;
        ++i;
        Json * id = i;
        if ( !name->valid( Json::String ) ||
             !arguments->valid( Json::Object ) ||
             !id->valid( Json::String ) ) {
            fail( 400, "urn:ietf:params:jmap:error:notRequest",
                  "Each method call is a triple of name, arguments and id" );
            return;
        }

        if ( start( name->ascii(), arguments, id->ascii() ) )
            return;

        Json * answer = call( name->ascii(), arguments );
        Json * response = Json::list();
        if ( answer ) {
            response->append( name );
            response->append( answer );
        }
        else {
            // Every method that would change something is absent, so
            // this is also the answer to Email/set and its friends.
            Json * e = Json::object();
            e->insert( "type", Json::string( EString( "unknownMethod" ) ) );
            response->append( Json::string( EString( "error" ) ) );
            response->append( e );
        }
        response->append( id );
        responses->append( response );
    }

    Json * r = Json::object();
    r->insert( "methodResponses", responses );
    r->insert( "sessionState", Json::string( EString( "1" ) ) );
    d->http->respond( "application/json", r->write() + "\n" );
}
