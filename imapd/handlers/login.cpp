#include "login.h"

#include "../imap.h"
#include "../auth/plain.h"


/*!  Constructs a simple Login handler. */

Login::Login()
    : Command()
{
}


/*! Parses arguments for the login command. */

void Login::parse()
{
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
    if ( plain.loginExists() && plain.password() == p )
        imap()->setLogin( n );
    else if ( n.isEmpty() )
        error( No, "login failed " );
    else
        error( No, "login failed for " + n );
    setState( Finished );
}
