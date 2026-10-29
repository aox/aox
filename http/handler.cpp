// Copyright Arnt Gulbrandsen, arnt@gulbrandsen.priv.no.

#include "handler.h"

#include "dict.h"
#include "allocator.h"


static Dict<HttpHandler> * handlers = 0;


/*! \class HttpHandler handler.h

    The HttpHandler class performs the right action for a single URL.
*/


/*! Registers this handler for \a path. */

HttpHandler::HttpHandler( const EString & path )
    : p( path )
{
    if ( !handlers ) {
        handlers = new Dict<HttpHandler>;
        Allocator::addEternal( handlers, "HTTP handlers" );
    }
    handlers->insert( path, this );
}


/*! Returns the path this handler serves. */

EString HttpHandler::path() const
{
    return p;
}


/*! Returns the handler registered for \a path, or a null pointer if
    nothing serves it.
*/

HttpHandler * HttpHandler::find( const EString & path )
{
    if ( !handlers )
        return 0;
    return handlers->find( path );
}
