// Copyright 2009 The Archiveopteryx Developers <info@aox.org>

/*! \class Anonymous anonymous.h
    Implements anonymous SASL authentication (RFC 2245)

    We issue an empty challenge and accept an email address in response.
    The authentication succeeds if a user named "anonymous" exists. The
    email address is logged.
*/

#include "anonymous.h"


/*! Creates an anonymous SASL authentication object on behalf of \a c */

Anonymous::Anonymous( EventHandler *c )
    : SaslMechanism( c, SaslMechanism::Anonymous )
{
    setState( AwaitingInitialResponse );
}


void Anonymous::parseResponse( const EString &r )
{
    log( "Anonymous login from '"+r+"'", Log::Debug );
    setState( Authenticating );
    setLogin( "anonymous" );
    setSecret( "" );
    execute();
}


void Anonymous::verify()
{
    setState( Succeeded );
}
