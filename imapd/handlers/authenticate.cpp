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
    allows it to participate in the challenge-response negotiation until
    it reaches a decision we can act upon.
*/

void Authenticate::execute()
{
    // First, create a mechanism handler.
    if ( !a ) {
        a = Authenticator::create( t );
        if ( !a ) {
            error( Bad, "Mechanism " + t + " not supported" );
            return;
        }

        imap()->reserve( this );
        a->setLogger( logger() );
    }

    // Perform C/R roundtrips until we can make up our mind.

    while ( a->state() != Authenticator::ResponseAccepted &&
            a->state() != Authenticator::ResponseRejected )
    {
        if ( a->state() == Authenticator::ChallengeNeeded ) {
            imap()->writeBuffer()->append( "+ "+ a->challenge().e64() +"\r\n" );
            a->setState( Authenticator::ChallengeIssued );
            r.truncate( 0 );
            return;
        }
        else if ( a->state() == Authenticator::ChallengeIssued &&
                  !r.isEmpty() )
        {
            // XXX: this may be buggy - if the response can be multiline
            // this can, depending on luck and the weather, consider any
            // integer number of lines to be the response. but can the
            // response be multiline? look into that later.
            a->respond( r.de64() );
            r.truncate( 0 );
        }

        // Have we made up our mind yet?
        if ( a->state() == Authenticator::ResponseRejected ) {
            imap()->reserve( 0 );
            error( No, "Sorry" );
        }
        else if ( a->state() == Authenticator::ResponseAccepted ) {
            setState( Finished );
            imap()->reserve( 0 );
            imap()->setLogin( a->login() );
        }
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
