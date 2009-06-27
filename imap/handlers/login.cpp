// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

#include "login.h"

#include "capability.h"
#include "imap.h"
#include "mechanism.h"


/*! \class Login login.h
    Performs plaintext authentication (RFC 3501 section 6.2.3)

    The client supplies us with a plaintext username and password, and
    we treat it as we would an AUTH=PLAIN request. (We should disallow
    this mechanism until after STARTTLS.)
*/

Login::Login()
    : m( 0 )
{
}


void Login::parse()
{
    space();
    n = astring();
    space();
    p = astring();
    end();
}


/*! This function creates a Plain SaslMechanism, bypasses CR negotiation
    by feeding it the data it would otherwise issue a challenge for, and
    waits for its verdict.

    In general, Authenticate is much preferrable, but some clients
    only implement Login.
*/

void Login::execute()
{
    if ( state() != Executing )
        return;

    if ( !m ) {
        m = SaslMechanism::create( "plain", this, imap() );
        if ( !m ) {
            error( No, "Plaintext authentication disallowed" );
            setRespTextCode( "ALERT" );
            return;
        }
        m->setState( SaslMechanism::Authenticating );
        m->setLogin( n );
        m->setSecret( p );
        m->execute();
    }

    if ( !m->done() )
        return;

    if ( m->state() == SaslMechanism::Succeeded ) {
        imap()->setUser( m->user(), "IMAP login" );
        setRespTextCode( "CAPABILITY " + Capability::capabilities( imap() ) );
    }
    else {
        error( No, "LOGIN failed for " + n.quoted() );
        setRespTextCode( "AUTHENTICATIONFAILED" );
    }

    finish();
}
