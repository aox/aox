#include "authenticate.h"

#include "imap.h"
#include "auth/authenticator.h"
#include "buffer.h"
#include "arena.h"
#include "scope.h"

/*! Constructs an generic Authenticate handler, for any mechanism. */

Authenticate::Authenticate()
    : a(0)
{
}


/*! Parses the initial bits of Authenticate, that is, the type. The
    rest is left for read().
*/

void Authenticate::parse()
{
    t = atom().lower();
    end();
}


/*! Verifies the authentication mechanism and offers the challenge.
    Later calls do nothing.
*/

void Authenticate::execute()
{
    if ( !a ) {
        // first time. look for an authenticator and fail if there's none.
        a = Authenticator::authenticator( t );
        if ( !a ) {
            error( Bad, "Mechanism " + t + " not supported" );
            return;
        }
        imap()->reserve( this );
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
