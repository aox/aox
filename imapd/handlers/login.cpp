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
    if ( plain.loginExists( n ) && plain.password( n ) == p )
        imap()->setState( IMAP::Authenticated );
    else
        error( No, "login failed" );
    setState( Finished );
}
