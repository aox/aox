#include "login.h"

#include "imap.h"


/*! \class Login login.h
    Performs plaintext authentication (RFC 3501, §6.2.3)

    The client supplies us with a plaintext username and password, and
    we treat it as we would an AUTH=PLAIN request. (We should disallow
    this mechanism until after STARTTLS.)
*/

/*! \reimp */

Login::Login()
    : m( 0 )
{
}


/*! \reimp */

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
    if ( !m ) {
        if ( !imap()->supports( "login" ) ) {
            error( Bad, "LOGIN is disabled" );
            finish();
            return;
        }
        m = new Plain( this );
        m->setLogin( n );
        m->setSecret( p );
    }

    m->query();
    if ( !m->done() )
        return;

    if ( m->state() == SaslMechanism::Succeeded )
        imap()->authenticated( m->uid(), n );
    else
        error( No, "LOGIN failed for '" + n + "'" );

    finish();
}
