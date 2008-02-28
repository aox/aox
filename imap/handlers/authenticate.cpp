// Copyright Oryx Mail Systems GmbH. All enquiries to info@oryx.com, please.

#include "authenticate.h"

#include "imap.h"
#include "scope.h"
#include "buffer.h"
#include "mechanism.h"
#include "capability.h"


/*! \class Authenticate authenticate.h
    Initiates SASL authentication (RFC 3501 section 6.2.2)

    This class oversees the SASL challenge-response negotiation, using a
    SaslMechanism subclass to handle the details of the client-selected
    authentication mechanism.

    Supports SASL as used by RFC 3501 and extended by RCC 4959.
*/

Authenticate::Authenticate()
    : m( 0 ), r( 0 )
{
}


/*! Parses the initial arguments to AUTHENTICATE (at least a mechanism
    name, and perhaps a SASL initial response as well).
*/

void Authenticate::parse()
{
    space();
    t = atom().lower();

    // Accept a Base64-encoded SASL initial response.
    if ( nextChar() == ' ' ) {
        char c;
        space();
        r = new String;
        while ( ( ( c = nextChar() ) >= '0' && c <= '9' ) ||
                ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) ||
                c == '+' || c == '/' || c == '=' )
        {
            step();
            r->append( c );
        }
    }

    end();
}


/*! Creates a SaslMechanism corresponding to the selected mechanism, and
    uses it to participate in a challenge-response negotiation until we
    reach a decision.

    Typically, we create a handler and issue a challenge, and are called
    again to read the response, which we accept or reject after a quick
    chat with the database.
*/

void Authenticate::execute()
{
    if ( state() != Executing )
        return;

    if ( !m ) {
        if ( !imap()->accessPermitted() ) {
            error( No, "TLS required for mail access" );
            setRespTextCode( "ALERT" );
            return;
        }

        m = SaslMechanism::create( t, this, imap() );
        if ( !m ) {
            error( No, "Mechanism " + t + " not available" );
            return;
        }

        imap()->reserve( this );
        m->readInitialResponse( r );
    }

    if ( !m->done() )
        return;

    if ( m->state() == SaslMechanism::Succeeded )
        imap()->setUser( m->user() );
    else if ( m->state() == SaslMechanism::Terminated )
        error( Bad, "authentication terminated" );
    else
        error( No, "sorry" );

    setRespTextCode( "CAPABILITY " + Capability::capabilities( imap() ) );
    finish();
}


/*! Tries to read a single response line from the client, and pass it to
    the SaslMechanism if it succeeds.
*/

void Authenticate::read()
{
    m->readResponse( imap()->readBuffer()->removeLine() );
}
