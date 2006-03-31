// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "digest-md5.h"

#include "configuration.h"
#include "allocator.h"
#include "string.h"
#include "list.h"
#include "entropy.h"
#include "md5.h"

#include <time.h>


struct Nonce
    : public Garbage
{
    String value;
    String count;
    uint time;
};

static List<Nonce> * cache;


class DigestData
    : public Garbage
{
public:
    DigestData()
        : stale( false ), cachedNonce( 0 )
    {}

    bool stale;
    String rspauth;
    String realm, nonce, qop;
    String cnonce, nc, response, uri;
    Nonce *cachedNonce;
};


/*! \class DigestMD5 digest-md5.h
    Implements SASL DIGEST-MD5 authentication (RFC 2831)

    The server sends a challenge containing various parameters which the
    client uses to compute a response. The server validates the response
    based on the stored secret, and responds with another challenge, to
    which the client must send an empty response.

    We don't support a SASL initial response for this mechanism yet; nor
    do we support its use for anything but authentication.
*/


DigestMD5::DigestMD5( EventHandler *c )
    : SaslMechanism( c ), d( new DigestData )
{
    setState( AwaitingInitialResponse );
    d->realm = Configuration::hostname();
}


String DigestMD5::challenge()
{
    String r;

    if ( d->rspauth.isEmpty() ) {
        d->nonce = Entropy::asString( 48 ).e64();
        d->qop = "auth";

        r = "realm=\"" + d->realm + "\", " +
            "nonce=\"" + d->nonce + "\", " +
            "qop=\""   + d->qop   + "\", " +
            "algorithm=md5-sess";

        if ( d->stale )
            r.append( ", stale=true" );
    }
    else {
        r = "rspauth=" + d->rspauth;
    }

    return r;
}


void DigestMD5::readResponse( const String &r )
{
    // Is this a response to our second challenge?
    if ( !d->rspauth.isEmpty() ) {
        if ( !r.isEmpty() ) {
            setState( Failed );
        }
        else {
            uint t = time(0);

            // Update our nonce cache for successful authentication.
            if ( d->cachedNonce ) {
                d->cachedNonce->count = d->nc;
                d->cachedNonce->time = t;
            }
            else {
                Nonce *cn = new Nonce;
                cn->value = d->nonce;
                cn->count = d->nc;
                cn->time = t;

                if ( !cache ) {
                    cache = new List<Nonce>;
                    Allocator::addEternal( cache, "Digest-MD5 nonce cache" );
                }
                cache->append( cn );
                if ( cache->count() > 128 )
                    delete cache->shift();
            }
            setState( Succeeded );
        }
        return;
    }

    // Parse the first client response.
    List< Variable > l;

    bool ok = parse( r, l );

    Variable *user = l.find( "username" );
    Variable *realm = l.find( "realm" );
    Variable *nonce = l.find( "nonce" );
    Variable *cnonce = l.find( "cnonce" );
    Variable *resp = l.find( "response" );
    Variable *qop = l.find( "qop" );
    Variable *uri = l.find( "digest-uri" );
    Variable *nc = l.find( "nc" );

    if ( !ok || l.isEmpty() ) {
        log( "Empty/unparsable DIGEST-MD5 response: <<" + r + ">>",
             Log::Error );
        setState( Failed );
        return;
    }

    require( user, "user" );
    require( realm, "realm" );
    require( nonce, "nonce" );
    require( cnonce, "cnonce" );
    require( uri, "uri" );

    String s;
    if ( qop && ( !qop->unique() || qop->value() != "auth" ) ) {
        s = "qop invalid in DIGEST-MD5 response: " + qop->value();
        setState( Failed );
    }
    if ( !nc ) {
        s = "nc not present in DIGEST-MD5 response";
        setState( Failed );
    }
    else if ( !nc->unique() ) {
        s = "nc not unique in DIGEST-MD5 response";
        setState( Failed );
    }
    else if ( nc->value().length() != 8 ) {
        s = "nc <<" + nc->value() + ">> has length " +
            fn( nc->value().length() ) + " (not 8) in DIGEST-MD5 response";
        setState( Failed );
    }
    if ( !resp ) {
        s = "resp not present in DIGEST-MD5 response";
        setState( Failed );
    }
    else if ( !resp->unique() ) {
        s = "resp not unique in DIGEST-MD5 response";
        setState( Failed );
    }
    else if ( resp->value().length() != 32 ) {
        s = "resp <<" + resp->value() + ">> has length " +
            fn( resp->value().length() ) + " (not 32) in DIGEST-MD5 response";
        setState( Failed );
    }
    if ( state() == Failed ) {
        log( "Full DIGEST-MD5 response was: <<" + r + ">>", Log::Debug );
        log( s, Log::Error );
        return;
    }

    uint n = nc->value().number( &ok, 16 );

    d->cachedNonce = 0;
    if ( ok && state() == AwaitingInitialResponse ) {
        String ncv = nonce->value().unquoted();
        List< Nonce >::Iterator it( cache );
        while ( it ) {
            if ( it->value == ncv )
                break;
            ++it;
        }

        if ( !it || n != it->count.number( 0, 16 )+1 ) {
            setState( IssuingChallenge );
            return;
        }
        else {
            d->cachedNonce = it;
            d->nonce = it->value;
        }
    }
    else if ( !ok || nonce->value().unquoted() != d->nonce || n != 1 ) {
        log( "DIGEST-MD5 response with bad nonce/nc.", Log::Error );
        setState( Failed );
        return;
    }

    setLogin( user->value().unquoted() );
    d->cnonce = cnonce->value().unquoted();
    d->response = resp->value();
    d->uri = uri->value().unquoted();
    d->qop = "auth";
    d->nc = nc->value();
}


/*! This private helpers checks that \a v is present, is unique and
    quoted. If either breaks, it logs an appropriate debug message
    (naming \a v \a n) and sets the state to Failed.
*/

void DigestMD5::require( class Variable * v, const String & n )
{
    String l;
    if ( !v )
        l = n + " is not present in DIGEST-MD5 response";
    else if ( !v->unique() )
        l = n + " is not unique in DIGEST-MD5 response";
    else if ( !v->value().isQuoted() )
        l = n + " is not quoted in DIGEST-MD5 response";
    if ( l.isEmpty() )
        return;

    log( l, Log::Debug );
    setState( Failed );
}


void DigestMD5::verify()
{
    String R, A1, A2;

    A1 = MD5::hash( login() +":"+ d->realm +":"+ storedSecret() )
         +":"+ d->nonce +":"+ d->cnonce;
    A2 = "AUTHENTICATE:" + d->uri;

    R = MD5::hash(
        MD5::hash( A1 ).hex() +":"+
        d->nonce +":"+ d->nc +":"+ d->cnonce +":"+ d->qop +":"+
        MD5::hash( A2 ).hex()
    );

    if ( R.hex() == d->response ) {
        setState( IssuingChallenge );

        if ( d->cachedNonce &&
             d->cachedNonce->time + 1800 < (uint)time( 0 ) )
        {
            d->stale = true;
            return;
        }

        R = MD5::hash(
            MD5::hash( A1 ).hex() +":"+
            d->nonce +":"+ d->nc +":"+ d->cnonce +":"+ d->qop +":"+
            MD5::hash( ":" + d->uri ).hex()
        );
        d->rspauth = R.hex();
        return;
    }

    if ( d->cachedNonce )
        setState( IssuingChallenge );
    else
        setState( Failed );
}


void DigestMD5::setChallenge( const String &s )
{
    List< Variable > l;
    Variable *v;

    if ( !parse( s, l ) )
        return;

    v = l.find( "realm" );
    if ( v )
        d->realm = v->value().unquoted();

    v = l.find( "nonce" );
    if ( v )
        d->nonce = v->value().unquoted();

    v = l.find( "qop" );
    if ( v )
        d->qop = v->value().unquoted();
}


/*! RFC 2831 defines "n#m( expr )" as a list containing at least n, and
    at most m repetitions of expr, separated by commas, and optional
    linear white space:

        ( *LWS expr *( *LWS "," *LWS expr ) )

    This function tries to parse \a s as #( name=["]value["] ), and adds
    each element to the list \a l. It returns true if the entire string
    could be parsed without error, and false otherwise.

    If a name occurs more than once in the string, its value is appended
    to the instance already in \a l.
*/

bool DigestMD5::parse( const String &s, List< Variable > &l )
{
    if ( s.stripWSP().isEmpty() )
        return true;

    uint start = 0;
    do {
        // Find the beginning of the next element, skipping qdstr.
        int i = start;
        bool quoted = false;
        while ( s[i] != '\0' ) {
            if ( s[i] == '\\' )
                i++;
            else if ( s[i] == '"' )
                quoted = !quoted;
            else if ( !quoted && s[i] == ',' )
                break;
            i++;
        }

        // There's one list element between s[ start..i ].
        String elem = s.mid( start, i-start ).stripWSP();
        start = i+1;

        if ( !elem.isEmpty() ) {
            int eq = elem.find( '=' );
            if ( eq < 0 )
                return false;

            // We should validate name and value.
            String name = elem.mid( 0, eq ).stripWSP().lower();
            String value = elem.mid( eq+1, elem.length()-eq ).stripWSP();
            Variable *v = l.find( name );

            if ( !v ) {
                v = new Variable;
                v->name = name;
                l.append( v );
            }
            v->values.append( new String( value ) );
        }
    } while ( start < s.length() );

    return true;
}
