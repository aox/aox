/*! \class Authenticate authenticate.h
    Initiates SASL authentication (RFC 3501, §6.2.2)

    This class oversees the SASL challenge-response negotiation, using a
    SaslMechanism subclass to handle the details of the client-selected
    authentication mechanism.
*/

#include "authenticate.h"

#include "arena.h"
#include "scope.h"
#include "buffer.h"
#include "imap.h"
#include "sasl/mechanism.h"


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
        while ( ( ( c = nextChar() ) >= '0' && c <= '9' ) ||
                ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) ||
                c == '+' || c == '/' )
            r.append( c );
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
    // First, create a mechanism handler.

    if ( !a ) {
        a = Authenticator::create( t, this );
        if ( !a ) {
            error( Bad, "Mechanism " + t + " not supported" );
            return;
        }
        imap()->reserve( this );
    }

    // Feed the handler until it can make up its mind.

    if ( a->state() == Authenticator::IssuingChallenge ) {
        imap()->writeBuffer()->append( "+ "+ a->challenge().e64() +"\r\n" );
        a->setState( Authenticator::AwaitingResponse );
        r.truncate( 0 );
        return;
    }
    else if ( a->state() == Authenticator::AwaitingResponse &&
              !r.isEmpty() )
    {
        a->readResponse( r.de64() );
        r.truncate( 0 );
    }

    if ( !a->done() )
        a->verify();

    if ( a->done() ) {
        if ( a->state() == Authenticator::Failed )
            error( No, "Sorry" );
        else
            imap()->setLogin( a->login() );

        imap()->reserve( 0 );
        setState( Finished );
    }
}


/*! Handles reading (and handling) responses, and possibly issuing new
    challenges. Basically all the interesting parts of authentication.
*/

void Authenticate::read()
{
    Buffer * b = imap()->readBuffer();

    uint i = 0;
    while ( i < b->size() && (*b)[i] != 10 )
        i++;
    if ( (*b)[i] == 10 ) {
        i++;
        // since we cannot cause database access in read(), we need to
        // store the response here and use it later, in execute(). the
        // length if r is magic: zero means "no response received",
        // nonzero means "response received".
        r.append( *b->string( i ) );
        {
            Scope x( imap()->arena() );
            b->remove( i );
        }
    }
}
