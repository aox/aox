/*! \class Login login.h
    Performs plaintext authentication (RFC 3501, §6.2.3)
*/

#include "login.h"

#include "imap.h"
#include "sasl/plain.h"


/*! Constructs a simple Login handler. */

Login::Login()
    : Command()
{
}


/*! Parses arguments for the login command. */

void Login::parse()
{
    space();
    n = astring();
    space();
    p = astring();
    end();
}


/*! Verifies that names and passwords match perfectly. */

void Login::execute()
{
    Plain plain;
    plain.setLogin( n );
    if ( plain.loginExists() && plain.secret() == p )
        imap()->setLogin( n );
    else if ( n.isEmpty() )
        error( No, "login failed " );
    else
        error( No, "login failed for " + n );
    setState( Finished );
}
